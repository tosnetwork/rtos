"""Partitioned original-database restart receipts and fixed launch arguments."""

from scenario_matrix import member_id, require_fields

RESTARTS = {
    "partition-restart-member2": 2,
    "partition-restart-member5": 5,
    "below-quorum-restart": 2,
}


def restart_arguments(name, library):
    result = [
        "--interrupt-rust-member",
        str(RESTARTS[name]),
        "--partition-restart",
        "--network-fault-seconds",
        "12",
        "--socket-mark-library",
        str(library),
    ]
    if name == "below-quorum-restart":
        result.append("--recovery-below-quorum")
    return result


def check_restart_partition(
    name, receipt, recovery, *, expired_member=False, signer_expiry=False
):
    member = RESTARTS[name]
    if signer_expiry and (name != "below-quorum-restart" or expired_member):
        raise ValueError("Signer expiry requires its member2 below-quorum restart")
    if expired_member and (
        member != 5
        or recovery.get("expired_full_node", {}).get("signing_authority_restored")
        is not False
        or recovery.get("vote")
        or recovery.get("leaders")
    ):
        raise ValueError("Expired partition recovery regained signing authority")
    if not isinstance(receipt, dict) or not isinstance(recovery, dict):
        raise TypeError("Missing partitioned restart receipts")
    require_fields(
        receipt,
        {
            "member": member,
            "phase": "recovered",
            "mode": "partition_during_original_database_restart",
            "interruption_returncode": -9,
            "isolated_rpc_timeout_observed": True,
            "manual_database_repair": False,
        },
    )
    require_fields(
        recovery,
        {
            "member": member,
            "phase": "recovered",
            "interruption_returncode": -9,
            "manual_database_repair": False,
            "all_six_applied_states_match": True,
            "successor_finality_checked": True,
            "workchain_states_match": True,
        },
    )
    # argparse emits floating-point seconds; JSON integers are equivalent.
    # Keep identity/weight/boolean fields strictly typed in require_fields.
    for field, expected in (
        ("settle_after_interruption_seconds", 12),
        ("hold_after_restart_seconds", 12),
        ("recovery_limit_seconds", 180),
    ):
        value = receipt.get(field)
        if type(value) not in (int, float) or value != expected:
            raise ValueError(f"Restart duration differs at {field}")
    elapsed = receipt.get("elapsed_seconds")
    if type(elapsed) not in (int, float) or not 24 <= elapsed <= 180:
        raise ValueError("Partition restart exceeded or omitted the original budget")
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
        raise ValueError("Partition receipt does not bind the original and new process")
    times = [
        receipt.get(key)
        for key in ("armed_at_unix", "restarted_at_unix", "restored_at_unix")
    ]
    if (
        any(type(value) not in (int, float) for value in times)
        or times[1] - times[0] < 12
        or times[2] - times[1] < 12
    ):
        raise ValueError(
            "Partition did not span interruption and restarted-process hold"
        )
    before, after = (
        receipt.get(key, {})
        for key in ("kernel_before_restart_hold", "kernel_after_restart_hold")
    )
    for stats in (before, after):
        if (
            stats.get("kind") != "netem"
            or stats.get("handle") != "30:"
            or type(stats.get("drops")) is not int
            or stats["drops"] < 0
        ):
            raise ValueError("Missing native restart partition counters")
    if after["drops"] <= before["drops"]:
        raise ValueError("Partition did not affect the restarted process")
    if (
        not receipt.get("final_checkpoint")
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
        raise ValueError(
            "Restart evidence lacks matching checkpoints or fresh participation"
        )
    if name == "below-quorum-restart":
        require_fields(
            receipt,
            {
                "survivor_kind": "historical_checkpoint_after_below_quorum_stall",
                "surviving_weight": 34 if signer_expiry else 30,
                "total_weight": 68 if signer_expiry else 60,
                "quorum_weight": 46 if signer_expiry else 40,
            },
        )
        observation = receipt.get("below_quorum_observation", {})
        require_fields(
            observation,
            {
                "phase": "observed_no_finality",
                "required_observe_seconds": 12,
                "manual_database_repair": False,
            },
        )
        plan = observation.get("plan", {})
        require_fields(
            plan,
            {
                "member": 2,
                "weights": (
                    {str(i): 17 for i in (0, 2, 4, 5)}
                    if signer_expiry
                    else {"0": 10, "2": 30, "4": 10, "5": 10}
                ),
                "total_weight": 68 if signer_expiry else 60,
                "quorum_weight": 46 if signer_expiry else 40,
                "surviving_weight": 34 if signer_expiry else 30,
                "survivor_members": [0, 4] if signer_expiry else [0, 4, 5],
                "live_endpoints": [0, 1, 3, 4, 5],
                "settle_seconds": 4,
                "observe_seconds": 12,
            },
        )
        if signer_expiry:
            require_fields(plan, {"unavailable_signer_members": [5]})
        count, duration = (
            observation.get("observation_count"),
            observation.get("observation_elapsed_seconds"),
        )
        if (
            type(count) is not int
            or count < 2
            or type(duration) not in (int, float)
            or not 12 <= duration <= 180
            or observation.get("block") != receipt["survivor_checkpoint"]
            or not observation.get("state_root_hash")
        ):
            raise ValueError("Missing complete below-quorum observation")
    else:
        require_fields(receipt, {"surviving_weight": 51, "total_weight": 68})
        survivors = {member_id(i) for i in (0, 2, 4, 5) if i != member}
        certificates = receipt.get("survivor_certificates", [])
        if not certificates:
            raise ValueError("No surviving-quorum certificate")
        for certificate in certificates:
            if (
                certificate.get("final_certificate_checked") is not True
                or len(certificate.get("validator_ids", [])) != 3
                or set(certificate["validator_ids"]) != survivors
                or certificate.get("verified_weight") != 51
            ):
                raise ValueError("Restarted member counted in surviving quorum")


def check_restart_cleanup(runtime, receipt):
    import json

    directory = runtime / "recovery-partition/injection"
    injection = json.loads((directory / "injection.json").read_text())
    if (
        injection.get("owned_qdisc") is not False
        or injection.get("mode") != "partition"
    ):
        raise ValueError("Restart partition was not removed")
    namespace = injection["namespace"]
    if (
        namespace["network"] == namespace["parent_network"]
        or namespace["user"] == namespace["parent_user"]
    ):
        raise ValueError("Restart partition used the parent namespace")
    statistics = json.loads((directory / "statistics.json").read_text())
    # statistics.json contains the latest tc sample, not the sampling history.
    for key in ("kernel_before_restart_hold", "kernel_after_restart_hold"):
        sampled = json.loads((directory.parent / f"{key}.json").read_text())
        if receipt[key] != sampled:
            raise ValueError("Restart partition counter differs from native output")
    if receipt["kernel_after_restart_hold"] not in statistics:
        raise ValueError("Final restart partition counter differs from native output")
