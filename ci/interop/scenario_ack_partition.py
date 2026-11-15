"""Bind ACK failure and packet isolation to one recovery and one deadline."""

import math

from scenario_ack import ack_arguments, check_ack_result
from scenario_matrix import require_fields
from scenario_restart import check_restart_partition, restart_arguments

ACK_PARTITIONS = {
    f"source-ack-partition-{mode}": f"source-ack-{mode}"
    for mode in ("sync-eio", "write-enospc")
}


def ack_partition_arguments(name, ack_library, packet_library):
    return (
        restart_arguments("partition-restart-member2", packet_library)
        + ack_arguments(ACK_PARTITIONS[name], ack_library)[2:]
        + ["--source-ack-partition-restart"]
    )


def check_ack_partition_result(name, combined, source, partition, recovery):
    check_ack_result(ACK_PARTITIONS[name], source, recovery)
    check_restart_partition("partition-restart-member2", partition, recovery)
    if not isinstance(combined, dict):
        raise TypeError("Missing combined ACK partition receipt")
    require_fields(
        combined,
        {
            "phase": "recovered",
            "member": 2,
            "mode": "source_ack_failure_and_partition_across_restart",
            "source_ack_fault": source["mode"],
            "source_phase": "recovered",
            "partition_phase": "recovered",
            "source_fault_removed_before_restart": True,
            "original_source_ack_recovered": True,
            "isolated_rpc_timeout_observed": True,
            "manual_database_repair": False,
        },
    )
    for field, expected in (
        ("recovery_limit_seconds", 180),
        ("hold_before_survivor_seconds", 12),
        ("hold_after_restart_seconds", 12),
    ):
        value = combined.get(field)
        if type(value) not in (int, float) or value != expected:
            raise ValueError("Combined ACK partition changed the original limits")
    start = combined.get("budget_started_at_unix")
    if (
        type(start) not in (int, float)
        or not math.isfinite(start)
        or start <= 0
        or start != source.get("budget_started_at_unix")
        or start != partition.get("budget_started_at_unix")
    ):
        raise ValueError("ACK and partition do not share the original budget")
    elapsed = combined.get("elapsed_seconds")
    if type(elapsed) not in (int, float) or not 24 <= elapsed <= 180:
        raise ValueError("Combined recovery omitted or exceeded its budget")
    error_time = source.get("native_error_observed_at_unix")
    armed = partition.get("armed_at_unix")
    restored = partition.get("restored_at_unix")
    if (
        any(
            type(value) not in (int, float) or not math.isfinite(value)
            for value in (error_time, armed, restored)
        )
        or not start <= error_time <= armed < restored
        or combined.get("native_error_observed_at_unix") != error_time
        or combined.get("partition_armed_at_unix") != armed
        or combined.get("restored_at_unix") != restored
    ):
        raise ValueError("Partition must follow the same native ACK refusal")
    for field in ("survivor_checkpoint", "final_checkpoint"):
        if combined.get(field) != partition.get(field):
            raise ValueError("Combined recovery changed its checkpoint")
    if (
        combined.get("intent_cut") is not None
        or combined.get("cold_bootstrap_body") is not None
    ):
        raise ValueError("Unexpected extra intent or cold-bootstrap scenario")
