"""Fresh, serial rotation scenarios using the existing native verification runner."""

import hashlib
import json
import subprocess
import time
from pathlib import Path

from binary_identity import require_rust_revision
from cpp_baseline import require_cpp_baseline
from scenario_ack import (
    ACKS,
    ack_arguments,
    ack_artifacts,
    check_ack_evidence,
    check_ack_result,
)
from scenario_ack_intent import (
    INTENTS,
    check_intent_evidence,
    check_intent_result,
    intent_arguments,
)
from scenario_ack_partition import (
    ACK_PARTITIONS,
    ack_partition_arguments,
    check_ack_partition_result,
)
from scenario_expiry import (
    check_expired_full_node_witness,
    check_expiry_authority_copies,
    check_expiry_evidence,
    check_expiry_raw_witness,
    check_passive_recovery_components,
    expiry_arguments,
)
from scenario_matrix import (
    MATRICES,
    check_matrix_result,
    make_matrix_profile,
    matrix_commands,
)
from scenario_observer import OBSERVER_PLAN, check_observer_result
from scenario_packet import (
    PACKETS,
    check_packet_cleanup,
    check_packet_result,
    packet_arguments,
    packet_artifacts,
)
from scenario_restart import (
    RESTARTS,
    check_restart_cleanup,
    check_restart_partition,
    restart_arguments,
)
from scenario_retention import (
    RETENTIONS,
    check_retention_evidence,
    check_retention_result,
    retention_arguments,
    retention_artifacts,
)

ROTATIONS = (
    frozenset(
        f"{family}-{mode}"
        for family in (
            "rotation",
            "exact-weight",
            "necessary-low-weight",
            "observer-budget",
        )
        for mode in ("control", "mixed")
    )
    | {"restart-member2", "restart-member5"}
    | set(PACKETS)
    | set(RESTARTS)
    | set(ACKS)
    | set(ACK_PARTITIONS)
    | set(INTENTS)
    | set(RETENTIONS)
    | {"expired-member-restart"}
)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def make_profile(name, template, now):
    if name not in ROTATIONS:
        raise ValueError("Scenario has no execution adapter")
    profile = {
        key: template[key]
        for key in (
            "schema",
            "cpp_revision",
            "global_version",
            "consensus",
            "auth_network_tag",
        )
    }
    profile.update(
        global_id=4,
        genesis_time=int(now),
        wallet_seed_label=f"rtos-scenario-{name}",
        activation_delay=120,
        successor_valid_for=10000,
        initial_members=[0, 1, 2, 3],
        successor_members=[0, 2, 4, 5],
        expected_zerostate=None,
        expected_workchain_zerostate=None,
    )
    if name.startswith(("exact-weight-", "necessary-low-weight-")):
        profile.update(
            initial_weights={"0": 30, "1": 10, "2": 11, "3": 9},
            successor_weights={"0": 9, "2": 11, "4": 10, "5": 30},
            weighted_quorum_pause=[0, 2],
        )
    if name.startswith("necessary-low-weight-"):
        profile.update(
            initial_weights={"0": 29, "1": 11, "2": 10, "3": 10},
            initial_probe_pause=[1],
        )
    if name == "below-quorum-restart":
        profile["successor_weights"] = {"0": 10, "2": 30, "4": 10, "5": 10}
    if name.startswith("observer-budget-"):
        profile["observer_budget"] = {
            key: value.copy() if isinstance(value, list) else value
            for key, value in OBSERVER_PLAN.items()
        }
    return profile


def check_result(name, result):
    """Require the driver's semantic receipts as well as its successful exit."""
    mixed = not name.endswith("-control")
    expected = (
        "mixed_membership_rotation_observed"
        if mixed
        else "cpp_membership_rotation_observed"
    )
    if result.get("status") != expected:
        raise ValueError("Scenario did not complete the required rotation mode")
    if (
        any(
            result.get(key) is not True
            for key in (
                "all_six_applied_mc_states_match",
                "independent_post_rotation_finality_qualified",
            )
        )
        or result.get("mixed_rotation_qualified") is not mixed
    ):
        raise ValueError("Missing verified rotation state/finality receipt")
    weighted = name.startswith(("exact-weight-", "necessary-low-weight-"))
    kinds = (
        ("mc_creators", "wc_creators", "mc_signers")
        if weighted or name.startswith("observer-budget-")
        else ("mc_creators", "wc_creators")
    )
    for phase in ("before", "after"):
        for kind in kinds:
            if len(result.get("epochs", {}).get(phase, {}).get(kind, {})) != 4:
                raise ValueError("Incomplete creator/signer epoch")
    weighted = name.startswith(("exact-weight-", "necessary-low-weight-"))
    low_weight = name.startswith("necessary-low-weight-")
    for field, needed, weight, members in (
        ("weighted_quorum", weighted, 40, [4, 5]),
        ("initial_probe", low_weight, 49, [0, 2, 3]),
    ):
        receipt = result.get(field)
        if not needed:
            if receipt is not None:
                raise ValueError("Unexpected weighted scenario receipt")
            continue
        if not receipt or receipt.get("phase") != "recovered":
            raise ValueError("Weighted recovery incomplete")
        if any(
            receipt.get(key) != value
            for key, value in {
                "total_weight": 60,
                "quorum_weight": 40,
                "surviving_weight": weight,
                "survivor_members": members,
                "same_processes": True,
                "manual_database_repair": False,
                "all_six_applied_states_match": True,
                "workchain_states_match": True,
            }.items()
        ):
            raise ValueError(
                "Weighted recovery assertion differs from declared scenario"
            )
    if name.startswith("observer-budget-"):
        check_observer_result(result.get("observer_budget"), mixed)
    elif result.get("observer_budget") is not None:
        raise ValueError("Unexpected observer budget receipt")
    if name in PACKETS:
        check_packet_result(name, result.get("network_fault"))
    elif result.get("network_fault") is not None:
        raise ValueError("Unexpected packet fault receipt")
    recovery = result.get("recovery")
    if name == "expired-member-restart":
        check_passive_recovery_components(
            result.get("source_ack_partition_restart"),
            result.get("source_ack_fault"),
            result.get("partition_restart"),
            recovery,
        )
    elif name in RETENTIONS:
        check_retention_result(name, result.get("source_retention_cut"), recovery)
    elif name in INTENTS:
        check_intent_result(
            name,
            result.get("source_ack_partition_restart"),
            result.get("source_ack_fault"),
            result.get("partition_restart"),
            recovery,
        )
    elif name in ACK_PARTITIONS:
        check_ack_partition_result(
            name,
            result.get("source_ack_partition_restart"),
            result.get("source_ack_fault"),
            result.get("partition_restart"),
            recovery,
        )
    elif name in ACKS:
        check_ack_result(name, result.get("source_ack_fault"), recovery)
    elif name in RESTARTS:
        check_restart_partition(name, result.get("partition_restart"), recovery)
    elif name.startswith("restart-member"):
        member = int(name[-1])
        if not recovery or any(
            recovery.get(key) != value
            for key, value in {
                "member": member,
                "phase": "recovered",
                "interruption_returncode": -9,
                "manual_database_repair": False,
                "all_six_applied_states_match": True,
                "successor_finality_checked": True,
                "workchain_states_match": True,
            }.items()
        ):
            raise ValueError("Original-database recovery incomplete")
        if not recovery.get("vote") or set(recovery.get("leaders", {})) != {
            "masterchain",
            "workchain",
        }:
            raise ValueError("Restarted member lacks its vote or creators")
    elif recovery is not None:
        raise ValueError("Unexpected restart receipt")
    if (
        name not in RESTARTS
        and name not in ACK_PARTITIONS
        and name not in INTENTS
        and name != "expired-member-restart"
        and result.get("partition_restart") is not None
    ):
        raise ValueError("Unexpected restart partition receipt")
    if (
        name not in ACKS
        and name not in ACK_PARTITIONS
        and name not in INTENTS
        and name != "expired-member-restart"
        and result.get("source_ack_fault") is not None
    ):
        raise ValueError("Unexpected source ACK fault receipt")
    if (
        name not in ACK_PARTITIONS
        and name not in INTENTS
        and name != "expired-member-restart"
        and result.get("source_ack_partition_restart") is not None
    ):
        raise ValueError("Unexpected combined ACK partition receipt")

    if name not in RETENTIONS and result.get("source_retention_cut") is not None:
        raise ValueError("Unexpected source retention cut")

    if name != "expired-member-restart" and result.get("signer_expiry") is not None:
        raise ValueError("Unexpected signer expiry receipt")


def execute(args, names, catalog):
    missing = [name for name in names if name not in ROTATIONS and name not in MATRICES]
    if missing:
        raise ValueError(f"Execution adapters not integrated: {', '.join(missing)}")
    required = (
        "snapshot",
        "profile_template",
        "rust_node",
        "validator_preparer",
        "block_checker",
        "rust_revision",
        "cpp_python",
        "output",
    )
    if any(getattr(args, key) is None for key in required):
        raise ValueError(
            "run requires all explicit binary, baseline, profile and output arguments"
        )
    source = Path(__file__).parent
    template = json.loads(args.profile_template.read_text())
    snapshot = json.loads((args.snapshot / "manifest.json").read_text())
    require_cpp_baseline(snapshot["cpp_source_commit"], template)
    require_rust_revision(args.rust_node, args.rust_revision)
    # Materialize no runtime directories until every selected adapter/input is checked.
    for name in names:
        (make_matrix_profile if name in MATRICES else make_profile)(name, template, 0)
    inputs = [
        args.rust_node,
        args.validator_preparer,
        args.block_checker,
        args.profile_template,
        args.snapshot / "manifest.json",
        catalog,
        *source.glob("*.py"),
    ]
    if any(
        name in PACKETS
        or name in RESTARTS
        or name in ACK_PARTITIONS
        or name in INTENTS
        or name == "expired-member-restart"
        for name in names
    ):
        inputs.extend(packet_artifacts(args, source))
    if any(
        name in ACKS
        or name in ACK_PARTITIONS
        or name in INTENTS
        or name == "expired-member-restart"
        for name in names
    ):
        inputs.extend(ack_artifacts(args, source))
    if any(name in RETENTIONS for name in names):
        inputs.extend(retention_artifacts(args, source))
    artifacts = {str(path.resolve()): digest(path) for path in inputs}
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    receipt = {
        "schema": 1,
        "status": "running",
        "selected_with_dependencies": names,
        "cpp_revision": snapshot["cpp_source_commit"],
        "rust_revision": args.rust_revision,
        "artifacts": artifacts,
        "completed": [],
        "qualification": "Selected bounded scenarios only; no all-scenarios or release verdict",
    }
    write(root / "suite.json", receipt)
    try:
        for name in names:
            if any(digest(path) != expected for path, expected in artifacts.items()):
                raise ValueError("A scenario suite input changed")
            case = root / name
            case.mkdir()
            profile = (make_matrix_profile if name in MATRICES else make_profile)(
                name, template, time.time()
            )
            write(case / "profile.json", profile)
            if name in MATRICES:
                prepare, run = matrix_commands(args, name, case)
            else:
                common = [
                    str(args.cpp_python),
                    str(source / "rotation_fixture.py"),
                    "--snapshot",
                    str(args.snapshot),
                    "--block-checker",
                    str(args.block_checker),
                    "--base-port",
                    "59800",
                ]
                prepare = common + [
                    "--profile",
                    str(case / "profile.json"),
                    "--output",
                    str(case / "genesis"),
                    "--prepare-genesis-only",
                ]
                run = common + [
                    "--profile",
                    str(case / "genesis/frozen-profile.json"),
                    "--output",
                    str(case / "runtime"),
                    "--timeout",
                    "240",
                    "--recovery-timeout",
                    "180",
                    "--workchain-creator-history",
                ]
                if not name.endswith("-control"):
                    run += [
                        "--rust-node",
                        str(args.rust_node),
                        "--validator-preparer",
                        str(args.validator_preparer),
                    ]
                if name.startswith("restart-member"):
                    run += ["--interrupt-rust-member", name[-1]]
            if name in PACKETS:
                run += packet_arguments(name, args.socket_mark_library)
            if name in RESTARTS:
                run += restart_arguments(name, args.socket_mark_library)
            if name in ACKS:
                run += ack_arguments(name, args.source_ack_fault_library)
            if name in ACK_PARTITIONS:
                run += ack_partition_arguments(
                    name, args.source_ack_fault_library, args.socket_mark_library
                )
            if name in INTENTS:
                run += intent_arguments(
                    name, args.source_ack_fault_library, args.socket_mark_library
                )
            if name in RETENTIONS:
                run += retention_arguments(name, args.source_retention_cut_library)
            if name == "expired-member-restart":
                run += expiry_arguments(
                    name, args.source_ack_fault_library, args.socket_mark_library
                )
            for label, command in (("prepare", prepare), ("run", run)):
                command = [
                    str(args.cpp_python),
                    str(source / "run_network_namespace.py"),
                    *command,
                ]
                invocation = {"command": command, "started": time.time()}
                write(case / f"{label}-invocation.json", invocation)
                with (case / f"{label}.log").open("w") as log:
                    process = subprocess.run(
                        command, stdout=log, stderr=log, check=False
                    )
                invocation.update(exit_code=process.returncode, ended=time.time())
                write(case / f"{label}-completion.json", invocation)
                if process.returncode:
                    raise RuntimeError(f"{name} {label} exited {process.returncode}")
            result_path = case / "runtime/result.json"
            result = json.loads(result_path.read_text())
            if name in MATRICES:
                check_matrix_result(name, result, profile)
            else:
                check_result(name, result)
                if name in PACKETS:
                    check_packet_cleanup(case / "runtime", result["network_fault"])
                if (
                    name in RESTARTS
                    or name in ACK_PARTITIONS
                    or name in INTENTS
                    or name == "expired-member-restart"
                ):
                    check_restart_cleanup(case / "runtime", result["partition_restart"])
                if (
                    name in ACKS
                    or name in ACK_PARTITIONS
                    or name in INTENTS
                    or name == "expired-member-restart"
                ):
                    check_ack_evidence(case / "runtime", result["source_ack_fault"])
            if name in INTENTS:
                check_intent_evidence(
                    case / "runtime",
                    result["source_ack_partition_restart"],
                    result["source_ack_fault"],
                    result["recovery"],
                    INTENTS[name],
                )
            if name in RETENTIONS:
                check_retention_evidence(
                    case / "runtime", result["source_retention_cut"], RETENTIONS[name]
                )
            if name == "expired-member-restart":
                runtime = case / "runtime"
                check_expiry_evidence(
                    runtime, result["signer_expiry"], result["recovery"], passive=True
                )
                check_expiry_raw_witness(runtime, result["signer_expiry"])
                check_expiry_authority_copies(runtime, result["signer_expiry"])
                check_expired_full_node_witness(
                    runtime, result["signer_expiry"], result["recovery"]
                )
            if any(digest(path) != expected for path, expected in artifacts.items()):
                raise ValueError("A scenario suite input changed during execution")
            receipt["completed"].append(
                {"id": name, "result_sha256": digest(result_path)}
            )
            write(root / "suite.json", receipt)
        receipt["status"] = "selected_scenarios_passed"
    except BaseException as error:
        receipt.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        write(root / "suite.json", receipt)
