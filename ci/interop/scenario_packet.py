"""Fixed packet cases, explicit native-tool provenance and kernel effect receipts."""

import hashlib
import json
from pathlib import Path

from scenario_matrix import member_id, require_fields

PACKETS = {
    f"packet-{mode}-member{member}": (mode, member)
    for mode in ("partition", "loss", "reorder", "duplicate")
    for member in (2, 5)
}


def file_hash(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def packet_artifacts(args, source):
    library = getattr(args, "socket_mark_library", None)
    record = getattr(args, "socket_mark_build_record", None)
    if library is None or record is None:
        raise ValueError(
            "Packet scenarios require a socket-mark library and its build record"
        )
    build = json.loads(record.read_text())
    native_source = source / "network_fault/socket_mark.c"
    if (
        Path(build["source"]).resolve() != native_source.resolve()
        or Path(build["library"]).resolve() != library.resolve()
    ):
        raise ValueError("Packet build record names different source or library")
    for path, meta in (
        (native_source, build["source_meta"]),
        (library, build["library_meta"]),
    ):
        if path.stat().st_size != meta["bytes"] or file_hash(path) != meta["sha256"]:
            raise ValueError("Packet native source/library differs from build receipt")
    return [native_source, library, record]


def packet_arguments(name, library):
    mode, member = PACKETS[name]
    return [
        "--network-fault",
        mode,
        "--network-fault-member",
        str(member),
        "--network-fault-seconds",
        "12",
        "--socket-mark-library",
        str(library),
    ]


def check_packet_result(name, receipt):
    mode, member = PACKETS[name]
    if not isinstance(receipt, dict):
        raise TypeError("Missing packet scenario receipt")
    require_fields(
        receipt,
        {
            "mode": mode,
            "member": member,
            "phase": "recovered",
            "same_process": True,
            "manual_database_repair": False,
            "all_six_applied_states_match": True,
            "workchain_states_match": True,
            "successor_finality_checked": True,
        },
    )
    if receipt.get("deadline_seconds") != 180:
        raise ValueError("Packet recovery deadline differs")
    elapsed = receipt.get("elapsed_seconds")
    armed, restored = receipt.get("armed_at_unix"), receipt.get("restored_at_unix")
    if (
        any(type(value) not in (float, int) for value in (elapsed, armed, restored))
        or not 12 <= elapsed <= 180
        or restored - armed < 12
    ):
        raise ValueError("Packet impairment/recovery timing is incomplete")
    stats = receipt.get("kernel_statistics", {})
    if stats.get("kind") != "netem" or stats.get("handle") != "30:":
        raise ValueError("Missing owned native netem statistics")
    for field in ("packets", "drops"):
        if type(stats.get(field)) is not int or stats[field] < 0:
            raise ValueError("Missing native packet counters")
    if mode in ("partition", "loss") and stats["drops"] <= 0:
        raise ValueError("Packet loss did not affect traffic")
    if mode == "reorder" and stats["drops"] != 0:
        raise ValueError("Reorder case included queue loss")
    if mode in ("reorder", "duplicate") and stats["packets"] <= 0:
        raise ValueError("Packet impairment carried no traffic")
    certificates = receipt.get("survivor_certificates", [])
    if not certificates:
        raise ValueError("No fresh survivor certificate")
    active = {member_id(i) for i in (0, 2, 4, 5)}
    for certificate in certificates:
        signers = certificate.get("validator_ids", [])
        if (
            certificate.get("final_certificate_checked") is not True
            or len(signers) != len(set(signers))
            or not set(signers) <= active
            or len(signers) * 17 < 46
            or certificate.get("verified_weight") != len(signers) * 17
        ):
            raise ValueError("Survivor certificate lacks current weighted quorum")
        if mode == "partition" and set(signers) != active - {member_id(member)}:
            raise ValueError("Partitioned member appears in fresh certificate")
    if mode == "partition":
        require_fields(
            receipt,
            {
                "isolated_rpc_timeout_observed": True,
                "surviving_weight": 51,
                "total_weight": 68,
            },
        )
    if not receipt.get("vote") or set(receipt.get("leaders", {})) != {
        "masterchain",
        "workchain",
    }:
        raise ValueError("Reconnected member lacks its vote or both chain creators")


def check_packet_cleanup(runtime, receipt):
    injection = json.loads(
        (runtime / "network-fault/injection/injection.json").read_text()
    )
    if (
        injection.get("owned_qdisc") is not False
        or injection.get("mode") != receipt["mode"]
    ):
        raise ValueError("Packet queue was not removed")
    namespace = injection["namespace"]
    if (
        namespace["network"] == namespace["parent_network"]
        or namespace["user"] == namespace["parent_user"]
    ):
        raise ValueError("Packet injection did not use a fresh namespace")
    statistics = json.loads(
        (runtime / "network-fault/injection/statistics.json").read_text()
    )
    if receipt["kernel_statistics"] not in statistics:
        raise ValueError(
            "Packet statistics receipt differs from retained native output"
        )
