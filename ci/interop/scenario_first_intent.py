"""Bind first-intent interruption to original bytes and real restart evidence."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from scenario_ack import ack_artifacts
from scenario_matrix import member_id, require_fields
from verify_intent_cut_evidence import verify_written_prefix

FIRST_INTENTS = {
    f"first-intent-{point}": point for point in ("before-write", "after-partial-write")
}


def first_intent_arguments(name, library):
    return [
        "--first-intent-cut-library",
        str(library),
        "--first-intent-cut-point",
        FIRST_INTENTS[name],
    ]


def first_intent_artifacts(args, source):
    # Both modes use the existing native source/intent interposer, without arming ACK faults.
    return ack_artifacts(
        SimpleNamespace(
            source_ack_fault_library=getattr(args, "first_intent_cut_library", None),
            source_ack_fault_build_record=getattr(
                args, "first_intent_cut_build_record", None
            ),
        ),
        source,
    )


def check_first_intent_result(name, result):
    receipt = result.get("first_intent_cut")
    if not isinstance(receipt, dict):
        raise TypeError("Missing first-intent receipt")
    require_fields(
        receipt,
        {
            "member": 2,
            "point": FIRST_INTENTS[name],
            "phase": "rotation_and_first_intent_recovery_verified",
            "manual_database_repair": False,
            "prior_complete_intents": 0,
            "normal_replay_completed": True,
            "stopped_state_verified": True,
            "interruption_returncode": -9,
            "pending_preserved_before_restart": True,
            "successor_mc_wc_post_restart_creators": True,
            "verified_post_restart_vote": True,
            "all_six_mc_four_wc_states_match": True,
            "recovery_limit_seconds": 180,
        },
    )
    replay, total = (
        receipt.get("elapsed_seconds"),
        receipt.get("total_acceptance_elapsed_seconds"),
    )
    if (
        type(replay) not in (int, float)
        or type(total) not in (int, float)
        or not 0 <= replay <= total <= 180
    ):
        raise ValueError("First-intent recovery/rotation exceeded original budget")
    old, new = receipt["old_process"], receipt["new_process"]
    # /proc starttime is retained as decimal text by the process owner.
    ticks = [p.get("start_ticks") for p in (old, new)]
    if (
        any(type(p.get("pid")) is not int or p["pid"] <= 0 for p in (old, new))
        or any(
            type(value) is not str
            or not value.isascii()
            or not value.isdecimal()
            or value.startswith("0")
            for value in ticks
        )
        or old["pid"] == new["pid"]
    ):
        raise ValueError("First-intent restart process identity differs")
    if int(ticks[1]) < int(ticks[0]):
        raise ValueError("First-intent restart process identity differs")
    member = member_id(2)
    after = result["epochs"]["after"]
    for kind in ("mc_creators", "wc_creators"):
        if after[kind].get(member, {}).get("local_collation_log") != "node-restart.log":
            raise ValueError("Missing post-restart successor creator")
    from first_intent_vote import post_restart_successor_vote

    vote = receipt.get("post_restart_vote", {})
    if (
        vote.get("validator_id") != member
        or not post_restart_successor_vote(
            vote.get("check", {}), member, receipt.get("restarted_at_unix")
        )
        or vote.get("block") != vote["check"]["block"]
    ):
        raise ValueError("Missing verified post-restart vote")


def check_first_intent_evidence(runtime, receipt, point):
    vote = receipt["post_restart_vote"]
    sample = Path(vote["sample_directory"])
    if not sample.resolve().is_relative_to((runtime / "checks").resolve()):
        raise ValueError("First-intent vote sample is outside owned checks")
    raw_vote = (sample / "epoch-checked.json").read_bytes()
    if (
        hashlib.sha256(raw_vote).hexdigest() != vote["checked_sha256"]
        or json.loads(raw_vote) != vote["check"]
    ):
        raise ValueError("First-intent vote differs from raw checked evidence")
    directory = runtime / "first-intent-cut"
    target, namespace = Path(receipt["path"]), Path(receipt["namespace"])
    owned = runtime / "rust-2/node_db/catchains/consensus/v2"
    if (
        not target.is_absolute()
        or ".." in target.parts
        or not namespace.resolve().is_relative_to(owned.resolve())
        or not target.resolve().is_relative_to(owned.resolve())
        or target.parent != namespace / "finality-intents"
    ):
        raise ValueError("First-intent path is outside the original member/namespace")

    def read_bound(name, hash_key, size_key=None):
        data = (directory / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != receipt.get(hash_key) or (
            size_key
            and (
                type(receipt.get(size_key)) is not int or len(data) != receipt[size_key]
            )
        ):
            raise ValueError("First-intent evidence differs: " + name)
        return data

    raw = read_bound("intent-before.json", "sha256", "bytes")
    intended = read_bound("intended.json", "intended_sha256", "intended_bytes")
    verify_written_prefix(raw, intended, point)
    record = json.loads(intended)
    if (
        record.get("schema") != 1
        or record.get("session_id") != receipt["session"]
        or record.get("slot") != receipt["slot"]
        or record.get("candidate_hash") != receipt["candidate_hash"]
        or target.name != f"{record['slot']}-{record['candidate_hash']}.tmp"
    ):
        raise ValueError("First-intent identity differs from intended record")
    start = read_bound("session-start.json", "session_start_sha256")
    manifest = (directory / "session-runtime.json").read_bytes()
    require_fields(
        json.loads(manifest),
        {
            "session": receipt["session"],
            "role": "validator",
            "shard_workchain": -1,
            "catchain_seqno": 0,
        },
    )
    if (namespace / "session-runtime.json").read_bytes() != manifest:
        raise ValueError("First-intent original runtime manifest changed")
    if (
        json.loads(start)
        != {
            k: v
            for k, v in record.items()
            if k not in ("slot", "candidate_hash", "certificate")
        }
        or (namespace / "finality-session-start.json").read_bytes() != start
    ):
        raise ValueError("First-intent durable session locator changed")
    inventory = json.loads(
        read_bound(
            "intent-directory-at-stop.json", "stopped_directory_inventory_sha256"
        )
    )
    if inventory != [
        {"path": target.name, "bytes": len(raw), "sha256": receipt["sha256"]}
    ]:
        raise ValueError("First-intent directory had prior/other intents")
    from first_intent_vote import verify_original_acceptance

    verify_original_acceptance(directory, receipt, record)
    outputs = target.parent / "outputs-v1" / target.with_suffix(".outputs").name
    if any(p.exists() for p in (target, target.with_suffix(".json"), outputs)):
        raise ValueError("First-intent original intent/output cleanup is incomplete")
    prepared = runtime / "rust-2/validator-prepared.json"
    if hashlib.sha256(prepared.read_bytes()).hexdigest() != receipt["prepared_sha256"]:
        raise ValueError("First-intent restart changed original authority")
    pid = receipt["old_process"]["pid"]
    status = (directory / "stopped-process.txt").read_text().splitlines()
    if (
        not any(
            line.startswith("State:") and line.split()[1:2] == ["T"] for line in status
        )
        or not any(
            line.startswith("Pid:") and line.split()[1:2] == [str(pid)]
            for line in status
        )
        or (directory / "native-stop.marker").read_text()
        != f"intent {point} pid={pid}: {target}\n"
    ):
        raise ValueError("First-intent native stop differs from original process")
    if (directory / "armed").exists() or not (directory / "disarmed").is_file():
        raise ValueError("First-intent fault remained armed")
