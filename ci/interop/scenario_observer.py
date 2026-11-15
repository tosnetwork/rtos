"""Semantic receipts for retired observers under successor quorum loss."""

import base64

from scenario_matrix import member_id, require_fields

OBSERVER_PLAN = {
    "pause_at_quorum": [],
    "pause_below_quorum": [0, 2],
    "settle_seconds": 4,
    "observe_seconds": 12,
}


def check_observer_result(receipt, mixed):
    if not isinstance(receipt, dict):
        raise TypeError("Observer scenario lacks its receipt")
    require_fields(
        receipt,
        {
            "phase": "recovered",
            "plan": OBSERVER_PLAN,
            "validator_count": 6,
            "total_weight": 68,
            "quorum_weight": 46,
            "active_members": [0, 2, 4, 5],
            "observer_members": [1, 3],
            "below_quorum_members": [1, 3, 4, 5],
            "below_quorum_active_members": [4, 5],
            "below_quorum_weight": 34,
            "same_processes": True,
            "manual_database_repair": False,
            "all_declared_mc_states_match": True,
            "all_declared_wc_states_match": True,
        },
    )
    certificates = receipt.get("survivor_certificates", [])
    if not certificates:
        raise ValueError("Observer scenario lacks authenticated successor finality")
    active_ids = {member_id(i) for i in (0, 2, 4, 5)}
    for certificate in certificates:
        signers = certificate.get("validator_ids", [])
        if (
            certificate.get("final_certificate_checked") is not True
            or not set(signers) <= active_ids
            or len(set(signers)) != len(signers)
            or len(signers) * 17 < 46
            or certificate.get("verified_weight") != len(signers) * 17
        ):
            raise ValueError(
                "Observer counted in successor certificate or quorum missing"
            )
    duration = receipt.get("observation_elapsed_seconds")
    if type(duration) not in (float, int) or not 12 <= duration < 240:
        raise ValueError("Observer scenario lacks the full bounded observation")
    if (
        type(receipt.get("observation_count")) is not int
        or receipt["observation_count"] <= 0
    ):
        raise ValueError("Observer scenario lacks responsive observations")
    before, after = (
        receipt.get("below_baseline", {}),
        receipt.get("below_final_references", {}),
    )
    if set(before) != {"1", "3", "4", "5"} or set(after) != set(before):
        raise ValueError("Observer/current endpoints missing")
    for index, reference in before.items():
        if any(
            not reference.get(key) or reference[key] != after[index].get(key)
            for key in ("init", "last", "state_root_hash")
        ):
            raise ValueError("Below-quorum observer/current finalized state changed")
    if set(receipt.get("votes", {})) != {"0", "2"} or set(
        receipt.get("leaders", {})
    ) != {"0", "2"}:
        raise ValueError("Resumed active members lack participation")
    if any(
        set(chains) != {"masterchain", "workchain"}
        for chains in receipt["leaders"].values()
    ):
        raise ValueError("Resumed member lacks both chain creators")
    for field in ("roles_before", "roles_after"):
        roles = receipt.get(field, {})
        if set(roles) != ({"1", "2", "3", "5"} if mixed else {"1", "3"}):
            raise ValueError("Incomplete successor runtime role evidence")
        for index, role in roles.items():
            is_rust = mixed and index in {"2", "3", "5"}
            if role.get("language") != ("rust" if is_rust else "cpp"):
                raise ValueError("Runtime role language differs from scenario")
            if is_rust:
                runtime = role.get("runtime", {})
                if not {"validator_index", "session", "catchain_seqno"} <= set(runtime):
                    raise ValueError("Incomplete Rust session role")
                expected = "observer" if index == "3" else "validator"
                if (
                    runtime.get("role") != expected
                    or runtime.get("shard_workchain") != -1
                ):
                    raise ValueError("Incorrect successor masterchain role")
                local_index = runtime.get("validator_index")
                if expected == "observer":
                    if local_index is not None:
                        raise ValueError("Retired Rust observer has a validator index")
                elif type(local_index) is not int or not 0 <= local_index < 4:
                    raise ValueError("Active Rust member lacks a validator index")
                if field == "roles_before":
                    session = base64.b64decode(
                        certificates[0]["session_id"], validate=True
                    ).hex()
                    if runtime.get("session") != session:
                        raise ValueError(
                            "Runtime role belongs to another consensus session"
                        )
            else:
                cc = role.get("catchain_seqno")
                line = role.get("observer_log", "")
                if (
                    type(cc) is not int
                    or f"valgroup(-1,8000000000000000).observer.{cc}.SimplexPool"
                    not in line
                    or "Observer group started" not in line
                ):
                    raise ValueError(
                        "Native retired member lacks observer startup evidence"
                    )
