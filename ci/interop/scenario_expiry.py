"""Verify finite signer expiry without renewing the original authority."""

import hashlib
import json
from pathlib import Path

from scenario_matrix import member_id, require_fields

EXPIRIES = frozenset({"signer-expiry", "expired-member-restart"})


def check_expiry_evidence(runtime, receipt, recovery, *, passive=False):
    if not isinstance(receipt, dict):
        raise TypeError("Missing natural expiry receipt")
    require_fields(
        receipt,
        {
            "phase": "expired_member_restarted_without_signing"
            if passive
            else "recovered_with_peer_still_expired",
            "manual_database_repair": False,
            "clock_adjusted": False,
            "authority_unchanged": True,
            "post_expiry_all_six_states_match": True,
        },
    )
    plan = receipt["plan"]
    require_fields(
        plan,
        {
            "member": 5,
            "interrupted_member": 5 if passive else 2,
            "quorum_weight": 46,
            "total_weight": 68,
            "surviving_weight_during_interruption": 51 if passive else 34,
            "surviving_weight_after_restart": 51,
        },
    )
    expiry = plan.get("expire_at")
    observed = receipt.get("observed_at_unix")
    if (
        type(expiry) is not int
        or type(observed) not in (int, float)
        or not observed >= expiry
    ):
        raise ValueError("Signer refusal was not observed after finite expiry")
    elapsed, limit = (
        receipt.get("elapsed_seconds"),
        receipt.get("recovery_limit_seconds"),
    )
    if (
        type(limit) not in (int, float)
        or limit != 180
        or type(elapsed) not in (int, float)
        or not 0 <= elapsed <= 180
    ):
        raise ValueError("Signer expiry exceeded original budget")
    directory = runtime / "signer-expiry"
    profile = json.loads((directory / "original-profile.json").read_text())
    schedule = json.loads((directory / "original-schedule.json").read_text())
    if (
        profile["expire_at"] != expiry
        or schedule["expire_at"] != expiry
        or profile["session"] != receipt["session"]
        or profile["validator"] != hashlib.sha256(b"n6-validator-id-5").hexdigest()
    ):
        raise ValueError("Signer authority differs from original finite expiry")
    bindings = receipt.get("authority_file_hashes", {})
    if len(bindings) != 3:
        raise ValueError("Missing original authority bindings")
    for path, digest in bindings.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise ValueError("Signer authority changed after observation")
    certificates = receipt.get("post_expiry_certificates", [])
    survivors = {member_id(i) for i in (0, 2, 4)}
    if not certificates or any(
        c.get("final_certificate_checked") is not True
        or set(c.get("validator_ids", [])) != survivors
        or len(c["validator_ids"]) != 3
        or c.get("verified_weight") != 51
        for c in certificates
    ):
        raise ValueError("Post-expiry finality contains an expired signer")
    if not receipt.get("last_checkpoint") or receipt["last_checkpoint"] != recovery.get(
        "last_checkpoint"
    ):
        raise ValueError("Expiry recovery checkpoint differs")
    expected = f"Session {receipt['session']} broadcast_vote: failed to sign vote: "
    if receipt.get("refusal_line") not in (
        expected + "signing generation expired and retired",
        expected + "signing journal stopped/retired",
    ):
        raise ValueError("Signing refusal belongs to a different session")
    if "signing generation expired and retired" not in receipt.get("expiry_line", ""):
        raise ValueError("Missing natural signing expiry observation")
    if passive:
        require_fields(receipt, {"old_process_replaced": True})
        if (
            receipt.get("new_pid") != recovery.get("new_process", {}).get("pid")
            or receipt.get("new_pid") == receipt.get("pid")
            or receipt.get("new_start_ticks")
            != recovery.get("new_process", {}).get("start_ticks")
        ):
            raise ValueError("Expired full node process differs")
    else:
        require_fields(receipt, {"same_expired_process": True})


def check_expiry_raw_witness(runtime, receipt):
    directory = runtime / "signer-expiry"
    sample = Path(receipt["post_expiry_sample"])
    if not sample.resolve().is_relative_to(directory.resolve()):
        raise ValueError("Expiry witness is outside its owned evidence directory")
    checked = json.loads((sample / "checked.json").read_text())
    if checked.get("block") != receipt.get("post_expiry_block") or checked.get(
        "verified_final_certificates"
    ) != receipt.get("post_expiry_certificates"):
        raise ValueError("Expiry certificate differs from native checked witness")
    if (
        type(checked.get("gen_utime")) is not int
        or checked["gen_utime"] <= receipt["plan"]["expire_at"] + 4
        or checked.get("key_block") is not False
        or not checked.get("verified_governing_key_blocks")
    ):
        raise ValueError("Expiry witness predates the authorized survivor finality")
    offset = receipt.get("log_offset")
    if type(offset) is not int or offset < 0:
        raise ValueError("Missing original expiry log offset")
    log = runtime / "rust-5/node.log"
    with log.open("rb") as stream:
        if stream.seek(0, 2) < offset:
            raise ValueError("Expiry log was truncated")
        stream.seek(offset)
        lines = stream.read().decode(errors="replace").splitlines()
    if receipt["expiry_line"] not in lines or receipt["refusal_line"] not in lines:
        raise ValueError("Expiry refusal is absent from the original process log")


def check_expiry_authority_copies(runtime, receipt):
    directory = runtime / "signer-expiry"
    owned = (runtime / "rust-5").resolve()
    bindings = receipt["authority_file_hashes"]
    expected = {
        "isolated-signing.json",
        "isolated-signing-schedule.json",
        "validator-prepared.json",
    }
    if len(bindings) != 3 or {Path(path).name for path in bindings} != expected:
        raise ValueError("Expiry authority bindings name different files")
    for path, digest in bindings.items():
        live = Path(path)
        if not live.resolve().is_relative_to(owned):
            raise ValueError("Expiry authority is outside the original member")
        if hashlib.sha256(live.read_bytes()).hexdigest() != digest:
            raise ValueError("Expiry authority differs from the original binding")
        saved = {
            "isolated-signing.json": "original-profile.json",
            "isolated-signing-schedule.json": "original-schedule.json",
        }.get(live.name)
        if (
            saved
            and hashlib.sha256((directory / saved).read_bytes()).hexdigest() != digest
        ):
            raise ValueError("Saved expiry authority differs from the bound live file")
    selected = json.loads((directory / "selected-runtime.json").read_text())
    if (
        selected.get("session") != receipt["session"]
        or selected.get("shard_workchain") != -1
        or selected.get("role") != "validator"
    ):
        raise ValueError("Expiry runtime does not bind the original MC signer")


def expiry_arguments(name, ack_library, packet_library):
    if name not in ("signer-expiry", "expired-member-restart"):
        raise ValueError("Unknown expiry scenario")
    member = "5" if name == "expired-member-restart" else "2"
    args = [
        "--interrupt-rust-member",
        member,
        "--partition-restart",
        "--network-fault-seconds",
        "12",
        "--socket-mark-library",
        str(packet_library),
        "--source-ack-fault",
        "sync-eio",
        "--source-ack-fault-library",
        str(ack_library),
        "--source-ack-partition-restart",
        "--signer-expiry-member",
        "5",
    ]
    args += (
        ["--expired-member-restart"]
        if name == "expired-member-restart"
        else ["--recovery-below-quorum"]
    )
    return args


def check_expired_full_node_witness(runtime, receipt, recovery):
    observation = recovery.get("expired_full_node")
    if (
        not isinstance(observation, dict)
        or receipt.get("full_node_observation") != observation
    ):
        raise ValueError("Expired full-node observations differ")
    require_fields(
        observation,
        {
            "member": 5,
            "required_observation_seconds": 12,
            "signing_authority_restored": False,
        },
    )
    if (
        observation.get("expire_at") != receipt["plan"]["expire_at"]
        or recovery.get("all_original_pending_intents_completed") is not True
    ):
        raise ValueError(
            "Expired full node changed authority or left original intents pending"
        )
    samples = observation.get("samples", [])
    if len(samples) < 3:
        raise ValueError("Expired full node needs three progressing samples")
    survivors = {member_id(i) for i in (0, 2, 4)}
    previous = None
    for sample in samples:
        elapsed = sample.get("elapsed_seconds")
        if type(elapsed) not in (int, float) or not 0 <= elapsed <= 180:
            raise ValueError("Expired full-node observation omitted elapsed time")
        directory = Path(sample["sample_directory"])
        if not directory.resolve().is_relative_to((runtime / "recovery").resolve()):
            raise ValueError("Expired full-node sample is outside original recovery")
        checked = json.loads((directory / "checked-with-workchain.json").read_text())
        wc = checked["workchain_check"]
        if (
            checked.get("block") != sample["block"]
            or wc.get("block") != sample["workchain"]
        ):
            raise ValueError("Expired full-node blocks differ from checked witnesses")
        if (
            checked.get("created_by") not in survivors
            or wc.get("created_by") not in survivors
            or wc.get("all_four_states_match_block_update") is not True
            or wc.get("masterchain_anchor_checked") is not True
        ):
            raise ValueError(
                "Expired member regained creator role or lost anchored state"
            )
        certificates = checked.get("verified_final_certificates", [])
        if not certificates or any(
            c.get("final_certificate_checked") is not True
            or len(c.get("validator_ids", [])) != 3
            or set(c["validator_ids"]) != survivors
            or c.get("verified_weight") != 51
            for c in certificates
        ):
            raise ValueError("Expired member regained certificate vote")
        if (
            checked["gen_utime"] <= recovery["restarted_at_unix"]
            or wc["gen_utime"] <= recovery["restarted_at_unix"]
        ):
            raise ValueError("Expired full-node sample predates restart")
        if previous and (
            sample["block"]["seqno"] <= previous["block"]["seqno"]
            or elapsed < previous["elapsed_seconds"]
        ):
            raise ValueError("Expired full-node samples did not progress")
        previous = sample
    if (
        samples[-1]["elapsed_seconds"] - samples[0]["elapsed_seconds"] < 12
        or samples[-1]["workchain"]["seqno"] <= samples[0]["workchain"]["seqno"]
    ):
        raise ValueError("Expired full-node observation was shortened")
    from expired_member_restart_fixture import ExpiredFullNodeAcceptance

    acceptance = ExpiredFullNodeAcceptance(
        member_id, recovery["restarted_at_unix"], 0, 0, receipt["session"]
    )
    log = (runtime / "rust-5/node-restart.log").read_text(errors="replace")
    if acceptance.refusal(log) != observation.get("refusal_line"):
        raise ValueError("Expired full node lacks original-session admission refusal")


def check_passive_recovery_components(combined, source, partition, recovery):
    from scenario_ack import check_ack_result
    from scenario_restart import check_restart_partition

    check_ack_result("source-ack-sync-eio", source, recovery, expired_member=True)
    check_restart_partition(
        "partition-restart-member5", partition, recovery, expired_member=True
    )
    require_fields(
        combined,
        {
            "phase": "recovered",
            "member": 5,
            "mode": "source_ack_failure_and_partition_across_restart",
            "source_ack_fault": "sync-eio",
            "source_phase": "recovered",
            "partition_phase": "recovered",
            "source_fault_removed_before_restart": True,
            "original_source_ack_recovered": True,
            "isolated_rpc_timeout_observed": True,
            "manual_database_repair": False,
        },
    )
    start = combined.get("budget_started_at_unix")
    if (
        type(start) not in (int, float)
        or not start > 0
        or start != source.get("budget_started_at_unix")
        or start != partition.get("budget_started_at_unix")
    ):
        raise ValueError("Expired recovery components do not share original budget")
    for key, expected in [
        ("recovery_limit_seconds", 180),
        ("hold_before_survivor_seconds", 12),
        ("hold_after_restart_seconds", 12),
    ]:
        value = combined.get(key)
        if type(value) not in (int, float) or value != expected:
            raise ValueError("Expired recovery changed limits")
    elapsed = combined.get("elapsed_seconds")
    if type(elapsed) not in (int, float) or not 24 <= elapsed <= 180:
        raise ValueError("Expired recovery exceeded original budget")
    for key in ["survivor_checkpoint", "final_checkpoint"]:
        if combined.get(key) != partition.get(key):
            raise ValueError("Expired recovery changed checkpoint")
    for key, nested in [
        ("native_error_observed_at_unix", source.get("native_error_observed_at_unix")),
        ("partition_armed_at_unix", partition.get("armed_at_unix")),
        ("restored_at_unix", partition.get("restored_at_unix")),
    ]:
        if combined.get(key) != nested:
            raise ValueError("Expired recovery changed event identity")
    error = source.get("native_error_observed_at_unix")
    armed = partition.get("armed_at_unix")
    restored = partition.get("restored_at_unix")
    if (
        any(type(t) not in (int, float) for t in [error, armed, restored])
        or not start <= error <= armed < restored
    ):
        raise ValueError("Expired recovery event order differs")
    if (
        combined.get("intent_cut") is not None
        or combined.get("cold_bootstrap_body") is not None
    ):
        raise ValueError("Unexpected additional recovery case")
