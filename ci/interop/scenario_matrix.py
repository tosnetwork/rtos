"""Fixed full-committee matrix profiles and semantic result requirements."""

import base64
import hashlib
from pathlib import Path

from quorum_profile import matrix_threshold_plan, quorum_threshold

MATRICES = {f"matrix4-cpp{i}": (4, i, "healthy") for i in range(5)}
for size, mixed in ((3, 1), (6, 3)):
    for variant in ("healthy", "threshold"):
        for mode, cpp in (("control", size), ("mixed", mixed)):
            MATRICES[f"matrix{size}-{variant}-{mode}"] = (size, cpp, variant)
for mode, cpp in (("control", 6), ("mixed", 3)):
    MATRICES[f"matrix6-low-weight-majority-{mode}"] = (6, cpp, "low_weight_majority")


def member_id(index):
    return base64.b64encode(
        hashlib.sha256(f"n6-validator-id-{index}".encode()).digest()
    ).decode()


def make_matrix_profile(name, template, now):
    count, cpp, variant = MATRICES[name]
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
        global_id=3,
        genesis_time=int(now),
        genesis_wallet_seed_label=f"rtos-scenario-{name}",
        bootstrap_validator_set_valid_for=2000000000,
        validator_count=count,
        shard_validators=count,
        economics="cpp-local-test-default",
        expected_zerostate=None,
        expected_workchain_zerostate=None,
    )
    if variant != "healthy":
        plan = {
            "pause_at_quorum": [2] if count == 3 else [1, 5],
            "pause_below_quorum": [1] if count == 3 else [3],
            "settle_seconds": 4,
            "observe_seconds": 12,
        }
        if variant == "low_weight_majority":
            profile["validator_weights"] = {
                str(i): 30 if i == 5 else 6 for i in range(6)
            }
            plan.update(kind=variant, pause_at_quorum=[], pause_below_quorum=[5])
        profile["threshold_fault"] = plan
    matrix_threshold_plan(profile, cpp)
    return profile


def matrix_commands(args, name, case):
    count, cpp, _ = MATRICES[name]
    common = [
        str(args.cpp_python),
        str(Path(__file__).with_name("mixed_matrix.py")),
        "--snapshot",
        str(args.snapshot),
        "--rust-node",
        str(args.rust_node),
        "--validator-preparer",
        str(args.validator_preparer),
        "--block-checker",
        str(args.block_checker),
        "--rust-revision",
        args.rust_revision,
        "--cpp-count",
        str(cpp),
        "--base-port",
        "59800",
    ]
    prepare = common + [
        "--genesis-profile",
        str(case / "profile.json"),
        "--output",
        str(case / "genesis"),
        "--prepare-genesis-only",
    ]
    run = common + [
        "--genesis-profile",
        str(case / "genesis/frozen-profile.json"),
        "--output",
        str(case / "runtime"),
        "--timeout",
        "180",
        "--verify-certificates",
        "--verify-workchain",
    ]
    if count == 4 and cpp:
        run.append("--workchain-creator-history")
    return prepare, run


def require_fields(actual, expected):
    for key, value in expected.items():
        if type(actual.get(key)) is not type(value) or actual[key] != value:
            raise ValueError(f"Matrix receipt differs at {key}")


def check_matrix_result(name, result, profile):
    count, cpp, variant = MATRICES[name]
    require_fields(
        result,
        {
            "status": "all_four_creators_accepted_with_matching_states"
            if count == 4
            else "all_declared_creators_accepted_with_matching_states",
            "validator_count": count,
            "cpp_count": cpp,
            "rust_count": count - cpp,
            "control_kind": "all_cpp"
            if cpp == count
            else "all_rust"
            if cpp == 0
            else "mixed",
            "final_certificates_required": True,
            "workchain_states_required": True,
            "workchain_creator_history": count == 4 and cpp > 0,
        },
    )
    identities = {member_id(i) for i in range(count)}
    if any(
        set(result.get(key, {})) != identities
        for key in ("creators", "workchain_creators")
    ):
        raise ValueError("Matrix lacks a declared MC/WC creator")
    for key in ("common_state_checkpoints", "workchain_state_checkpoints"):
        if type(result.get(key)) is not int or result[key] <= 0:
            raise ValueError("Matrix lacks full state checkpoints")
    fault = result.get("threshold_fault")
    if variant == "healthy":
        if fault is not None:
            raise ValueError("Unexpected matrix fault")
        return
    if not isinstance(fault, dict):
        raise TypeError("Missing threshold fault receipt")
    plan = matrix_threshold_plan(profile, cpp)
    weights = {
        i: profile.get("validator_weights", {}).get(str(i), 17) for i in range(count)
    }
    total = sum(weights.values())
    survivors = [i for i in range(count) if i not in plan["pause_at_quorum"]]
    below = [i for i in survivors if i not in plan["pause_below_quorum"]]
    require_fields(
        fault,
        {
            "phase": "recovered",
            "plan": plan,
            "validator_count": count,
            "total_weight": total,
            "quorum_weight": quorum_threshold(total),
            "survivor_members": survivors,
            "below_quorum_members": below,
            "below_quorum_weight": sum(weights[i] for i in below),
            "positive_kind": "high_weight_required"
            if variant == "low_weight_majority"
            else "exact_quorum",
            "same_processes": True,
            "manual_database_repair": False,
            "all_declared_mc_states_match": True,
            "all_declared_wc_states_match": True,
        },
    )
    certificates = fault.get("survivor_certificates", [])
    if not certificates:
        raise ValueError("Missing threshold certificate")
    identity_weights = {member_id(i): weight for i, weight in weights.items()}
    for certificate in certificates:
        signers = certificate.get("validator_ids", [])
        if (
            not signers
            or len(set(signers)) != len(signers)
            or not set(signers) <= set(identity_weights)
            or certificate.get("final_certificate_checked") is not True
        ):
            raise ValueError("Invalid threshold certificate signers")
        signed_weight = sum(identity_weights[signer] for signer in signers)
        if certificate.get(
            "verified_weight"
        ) != signed_weight or signed_weight < quorum_threshold(total):
            raise ValueError(
                "Threshold certificate has insufficient or inconsistent weight"
            )
        if variant == "low_weight_majority":
            if member_id(5) not in signers:
                raise ValueError("High-weight member absent from certificate")
        elif set(signers) != {
            member_id(i) for i in survivors
        } or signed_weight != quorum_threshold(total):
            raise ValueError("Certificate is not the declared exact quorum")
    elapsed = fault.get("observation_elapsed_seconds")
    if type(elapsed) not in (int, float) or not 12 <= elapsed < 180:
        raise ValueError("Missing full bounded below-quorum observation")
    if (
        type(fault.get("observation_count")) is not int
        or fault["observation_count"] <= 0
    ):
        raise ValueError("Missing responsive observations")
    baseline, final = (
        fault.get("below_baseline", {}),
        fault.get("below_final_references", {}),
    )
    if set(baseline) != {str(i) for i in below} or set(final) != set(baseline):
        raise ValueError("Below-quorum endpoints incomplete")
    for index, previous in baseline.items():
        if any(
            not previous.get(key) or final[index].get(key) != previous[key]
            for key in ("last", "state_root_hash")
        ):
            raise ValueError("Below-quorum finalized identity/state changed")
    restored = {str(i) for i in plan["pause_at_quorum"] + plan["pause_below_quorum"]}
    if (
        set(fault.get("votes", {})) != restored
        or set(fault.get("leaders", {})) != restored
    ):
        raise ValueError("Restored members lack fresh participation")
    if any(
        set(value) != {"masterchain", "workchain"}
        for value in fault["leaders"].values()
    ):
        raise ValueError("Restored member lacks both chain creators")
