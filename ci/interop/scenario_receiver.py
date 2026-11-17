"""Require an owned nonvoting receiver's exact body/state and teardown evidence."""

import json
from pathlib import Path

from mixed_matrix import digest, identity
from receiver_evidence import require_receiver_check
from scenario_matrix import require_fields

RECEIVER_PLAN = {
    "cpp_nonvoting": 1,
    "issuer_member": 0,
    "slot": 0,
    "valid_for_seconds": 3600,
}


def check_receiver_result(receipt):
    if not isinstance(receipt, dict):
        raise TypeError("Missing propagation receiver receipt")
    require_fields(
        receipt,
        {
            "role": "cpp_nonvoting_propagation_receiver",
            "committee_member": False,
            "consensus_keys_configured": False,
            "issuer_member": 0,
            "certificate_flags": 0,
            "certificate_slot": 0,
            "checkpoint_full_identity_matches": True,
        },
    )
    evidence = receipt.get("body_state_evidence")
    if not isinstance(evidence, dict):
        raise TypeError("Missing receiver body/state evidence")
    require_fields(
        evidence,
        {
            "source": "cpp_nonvoting_receiver",
            "receiver_body_and_full_state_checked": True,
        },
    )
    if identity(evidence["block"]) != identity(receipt["checkpoint"]) or int(
        receipt["latest"]["seqno"]
    ) < int(receipt["checkpoint"]["seqno"]):
        raise ValueError("Receiver checkpoint and body witness differ")
    if type(receipt.get("pid")) is not int or receipt["pid"] <= 0:
        raise ValueError("Receiver lacks an owned process")


def check_receiver_evidence(runtime, receipt, profile):
    check_receiver_result(receipt)
    directory = runtime / "propagation-receiver-evidence"
    evidence = receipt["body_state_evidence"]
    if Path(evidence["sample_directory"]).resolve() != directory.resolve():
        raise ValueError("Receiver sample is outside the owned directory")
    for name in ("sample", "checked"):
        if digest(directory / (name + ".json")) != evidence[name + "_sha256"]:
            raise ValueError("Receiver raw witness differs")
    checked = json.loads((directory / "checked.json").read_text())
    require_receiver_check(checked, receipt["checkpoint"], evidence["state_root_hash"])
    sample = json.loads((directory / "sample.json").read_text())
    if identity(sample["block"]["id"]) != identity(receipt["checkpoint"]):
        raise ValueError("Receiver sample body identity differs")
    if json.loads((runtime / "propagation-receiver.json").read_text()) != receipt:
        raise ValueError("Receiver saved receipt differs")
    if (
        profile.get("propagation_receiver") != RECEIVER_PLAN
        or receipt["certificate_expire_at"] != profile["genesis_time"] + 3600
    ):
        raise ValueError("Receiver authority differs from frozen profile")
    registry = json.loads((runtime / "processes.json").read_text())
    if registry.get("propagation_receivers", {}).get("cpp-receiver") != receipt["pid"]:
        raise ValueError("Receiver process differs from launched process")
    node = Path(receipt["directory"])
    if not node.resolve().is_relative_to((runtime / "network").resolve()):
        raise ValueError("Receiver node is outside the owned network")
    if json.loads((node / "config.json").read_text()).get("validators") != []:
        raise ValueError("Receiver has configured consensus validators")
    stopped = json.loads((runtime / "propagation-receiver-shutdown.json").read_text())
    require_fields(
        stopped,
        {
            "requested_signal": "SIGTERM",
            "alive_before_stop": True,
            "matches_pinned_tester_teardown": True,
        },
    )
    elapsed, limit = (
        stopped.get("elapsed_seconds"),
        stopped.get("teardown_limit_seconds"),
    )
    if (
        type(elapsed) not in (float, int)
        or type(limit) not in (float, int)
        or not 0 <= elapsed <= limit == 20
        or stopped.get("returncode") not in (0, -15)
    ):
        raise ValueError("Receiver teardown did not match the pinned native lifecycle")
