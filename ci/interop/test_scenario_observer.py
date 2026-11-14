"""Observer identity/authority and bounded availability receipt mutations."""

import base64
import copy
import unittest

from scenario_execution import check_result, make_profile
from scenario_matrix import member_id
from scenario_observer import OBSERVER_PLAN, check_observer_result
from test_scenario_execution import rotation_result


def receipt(mixed):
    session = bytes(range(32))
    roles = {
        "1": {
            "language": "cpp",
            "catchain_seqno": 7,
            "observer_log": "valgroup(-1,8000000000000000).observer.7.SimplexPool Observer group started",
        }
    }
    if mixed:
        for index in (2, 3, 5):
            roles[str(index)] = {
                "language": "rust",
                "runtime": {
                    "role": "observer" if index == 3 else "validator",
                    "validator_index": None if index == 3 else 1 if index == 2 else 3,
                    "shard_workchain": -1,
                    "catchain_seqno": 7,
                    "session": session.hex(),
                },
            }
    else:
        roles["3"] = copy.deepcopy(roles["1"])
    refs = {
        str(i): {
            "init": {"root": "genesis"},
            "last": {"seqno": 20},
            "state_root_hash": "state",
        }
        for i in (1, 3, 4, 5)
    }
    return {
        "phase": "recovered",
        "plan": copy.deepcopy(OBSERVER_PLAN),
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
        "survivor_certificates": [
            {
                "validator_ids": [member_id(i) for i in (0, 2, 4)],
                "verified_weight": 51,
                "final_certificate_checked": True,
                "session_id": base64.b64encode(session).decode(),
            }
        ],
        "observation_elapsed_seconds": 12.1,
        "observation_count": 58,
        "below_baseline": refs,
        "below_final_references": copy.deepcopy(refs),
        "votes": {"0": {}, "2": {}},
        "leaders": {str(i): {"masterchain": {}, "workchain": {}} for i in (0, 2)},
        "roles_before": roles,
        "roles_after": copy.deepcopy(roles),
    }


class ObserverScenarioTest(unittest.TestCase):
    def test_control_and_mixed(self):
        check_observer_result(receipt(False), False)
        check_observer_result(receipt(True), True)

    def test_current_and_retired_roles_cannot_be_interchanged(self):
        changes = [
            lambda r: r["roles_before"]["3"]["runtime"].update(role="validator"),
            lambda r: r["roles_after"]["3"]["runtime"].update(validator_index=0),
            lambda r: r["roles_before"]["2"]["runtime"].update(role="observer"),
            lambda r: r["roles_before"]["2"]["runtime"].update(session="00" * 32),
            lambda r: r["roles_after"].pop("3"),
            lambda r: r["roles_after"]["3"]["runtime"].pop("validator_index"),
            lambda r: r["roles_after"]["1"].update(observer_log=""),
            lambda r: r["survivor_certificates"][0]["validator_ids"].__setitem__(
                0, member_id(1)
            ),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                value = receipt(True)
                change(value)
                with self.assertRaises(ValueError):
                    check_observer_result(value, True)

    def test_negative_observation_and_recovery_are_required(self):
        changes = [
            lambda r: r.update(observation_elapsed_seconds=11.9),
            lambda r: r.update(observation_count=0),
            lambda r: r["below_final_references"]["1"].update(
                state_root_hash="changed"
            ),
            lambda r: r["below_final_references"].pop("3"),
            lambda r: r["votes"].pop("2"),
            lambda r: r["leaders"]["0"].pop("workchain"),
            lambda r: r.update(below_quorum_weight=68),
        ]
        for change in changes:
            value = receipt(True)
            change(value)
            with self.assertRaises(ValueError):
                check_observer_result(value, True)

    def test_dispatch_requires_observer_receipt_and_signer_epochs(self):
        result = rotation_result()
        with self.assertRaises(TypeError):
            check_result("observer-budget-mixed", result)
        result["observer_budget"] = receipt(True)
        check_result("observer-budget-mixed", result)
        with self.assertRaises(ValueError):
            check_result("rotation-mixed", result)
        result["epochs"]["after"]["mc_signers"].pop(0)
        with self.assertRaises(ValueError):
            check_result("observer-budget-mixed", result)

    def test_profile_retains_uniform_weights_and_bounded_plan(self):
        template = {
            "schema": 1,
            "cpp_revision": "ref",
            "global_version": 16,
            "consensus": {},
            "auth_network_tag": "tag",
            "weighted_quorum_pause": [0, 2],
        }
        profile = make_profile("observer-budget-mixed", template, 500)
        self.assertEqual(profile["observer_budget"], OBSERVER_PLAN)
        self.assertNotIn("weighted_quorum_pause", profile)
        self.assertNotIn("successor_weights", profile)
        profile["observer_budget"]["pause_below_quorum"].clear()
        self.assertEqual(OBSERVER_PLAN["pause_below_quorum"], [0, 2])


if __name__ == "__main__":
    unittest.main()
