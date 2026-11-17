"""Bootstrap adapters keep diagnostic control and checked mixed evidence distinct."""

import base64
import hashlib
import json
from pathlib import Path

from bootstrap_evidence import require_bootstrap_vote
from mixed_matrix import digest, identity
from receiver_evidence import require_receiver_check
from scenario_matrix import require_fields

BOOTSTRAPS = {"cpp-bootstrap", "unsigned-bootstrap", "required-rust-vote"}


def make_bootstrap_profile(name, template, now):
    if name not in BOOTSTRAPS:
        raise ValueError("Unknown bootstrap scenario")
    return {
        "schema": 1,
        "cpp_revision": template["cpp_revision"],
        "scenario": name,
        "active_rust_signing": name == "required-rust-vote",
        "minimum_height": 4,
        "timeout_seconds": 180,
    }


def bootstrap_commands(args, name, case):
    control = name == "cpp-bootstrap"
    command = [
        str(args.cpp_python),
        str(
            Path(__file__).with_name(
                "cpp_control.py" if control else "mixed_bootstrap.py"
            )
        ),
        "--snapshot",
        str(args.snapshot),
        "--output",
        str(case / "runtime"),
        "--base-port",
        "59800",
    ]
    if not control:
        command += [
            "--rust-node",
            str(args.rust_node),
            "--block-checker",
            str(args.block_checker),
            "--verify-full-state",
            "--min-height",
            "4",
            "--timeout",
            "180",
        ]
    if name == "required-rust-vote":
        command += [
            "--validator-preparer",
            str(args.validator_preparer),
            "--cpp-count",
            "2",
        ]
    return None, command


def check_bootstrap_result(name, result, profile, runtime):
    if result["cpp_commit"] != profile["cpp_revision"]:
        raise ValueError("Bootstrap reference revision differs")
    if name == "cpp-bootstrap":
        require_fields(
            result,
            {"status": "passed_cpp_control_only", "mixed_network_qualified": False},
        )
        native = json.loads((runtime / "result.json").read_text())
        if native != result["result"]:
            raise ValueError("Native control result differs from its receipt")
        require_fields(
            native,
            {
                "evidence_class": "DIAGNOSTIC_SCAFFOLDING_ONLY",
                "release_evidence_eligible": False,
                "consensus_correctness_verdict": "NOT_MADE_MERKLE_DIAGNOSIS_OPEN",
            },
        )
        if len(native["nodes"]) != 4:
            raise ValueError("Native control must have four nodes")
        return
    active = name == "required-rust-vote"
    require_fields(
        result,
        {
            "active_rust_signing": active,
            "committee_size": 4,
            "cpp_process_count": 2 if active else 3,
            "mixed_validator_qualified": False,
            "status": "rust_required_for_quorum_chain_progress"
            if active
            else "rust_public_sync_observed",
        },
    )
    evidence = result["body_state_evidence"]
    require_fields(
        evidence, {"source": "rust_bootstrap", "body_and_full_state_checked": True}
    )
    directory = runtime / "bootstrap-evidence"
    if Path(evidence["sample_directory"]).resolve() != directory.resolve():
        raise ValueError("Bootstrap evidence escaped the owned directory")
    for kind in ("sample", "checked"):
        if digest(directory / f"{kind}.json") != evidence[f"{kind}_sha256"]:
            raise ValueError("Bootstrap raw witness hash differs")
    sample = json.loads((directory / "sample.json").read_text())
    checked = json.loads((directory / "checked.json").read_text())
    target = result["applied_state_sample"]["rust"]["last"]
    if identity(evidence["block"]) != identity(target) or int(target["seqno"]) < 4:
        raise ValueError("Bootstrap checkpoint differs or lacks progress")
    if sample["masterchain_state"]["name"] != "rust-bootstrap":
        raise ValueError("Bootstrap state is not from Rust")
    if identity(sample["block"]["id"]) != identity(target):
        raise ValueError("Bootstrap body identity differs")
    for key in ("zerostate", "references", "rust"):
        if sample[key] != result["applied_state_sample"][key]:
            raise ValueError("Bootstrap checked observation differs")
    require_receiver_check(checked, target, evidence["state_root_hash"])
    config = json.loads((runtime / "rust/config.json").read_text())
    if digest(runtime / "rust/config.json") != result["config_sha256"]:
        raise ValueError("Bootstrap configuration changed")
    registry = json.loads((runtime / "process.json").read_text())
    if type(registry["rust_pid"]) is not int or registry["rust_pid"] <= 0:
        raise ValueError("Bootstrap lacks a launched Rust process")
    if (
        len(registry["cpp_pids"]) != result["cpp_process_count"]
        or any(
            type(pid) is not int or pid <= 0 for pid in registry["cpp_pids"].values()
        )
        or any(pid is not None for pid in registry["unused_cpp_pids"].values())
    ):
        raise ValueError("Bootstrap process topology differs")
    if json.loads((runtime / "rust-shutdown.json").read_text())["returncode"] not in (
        0,
        -15,
    ):
        raise ValueError("Bootstrap Rust process did not stop normally")
    if not active:
        if any(
            config.get(k)
            for k in ("validator_keys", "validator_key_ring", "pq_consensus")
        ):
            raise ValueError("Unsigned bootstrap has signing custody")
        if evidence["required_rust_vote"] is not None:
            raise ValueError("Unsigned bootstrap claims a required vote")
        return
    prepared = json.loads((runtime / "rust/validator-prepared.json").read_text())
    encode = lambda value: base64.b64encode(bytes.fromhex(value)).decode()
    master = next(s for s in prepared["sessions"] if s["masterchain"])
    required = {
        "validator_id": encode(prepared["validator_id"]),
        "committee": {
            encode(m["validator_id"]): m["weight"] for m in master["committee"]
        },
        "cpp_ids": [
            base64.b64encode(
                hashlib.sha256(f"n6-validator-id-{i}".encode()).digest()
            ).decode()
            for i in range(2)
        ],
    }
    if not config.get("pq_consensus") or not config.get("validator_key_ring"):
        raise ValueError("Required-vote bootstrap lacks configured custody")
    if require_bootstrap_vote(checked, required) != evidence["required_rust_vote"]:
        raise ValueError("Required vote differs from raw certificate")
