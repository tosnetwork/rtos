"""Reject weakened receipts and prevent partial launches of unsupported suites."""

import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scenario_execution import check_result, execute, make_profile


def rotation_result():
    return {
        "status": "mixed_membership_rotation_observed",
        "all_six_applied_mc_states_match": True,
        "independent_post_rotation_finality_qualified": True,
        "mixed_rotation_qualified": True,
        "epochs": {
            phase: {
                kind: {key: {} for key in range(4)}
                for kind in ("mc_creators", "wc_creators", "mc_signers")
            }
            for phase in ("before", "after")
        },
    }


def weighted_receipt(weight=40, members=None):
    return {
        "phase": "recovered",
        "total_weight": 60,
        "quorum_weight": 40,
        "surviving_weight": weight,
        "survivor_members": members or [4, 5],
        "same_processes": True,
        "manual_database_repair": False,
        "all_six_applied_states_match": True,
        "workchain_states_match": True,
    }


class ExecutionTest(unittest.TestCase):
    def test_unknown_adapter_refused_before_any_launch(self):
        with patch("scenario_execution.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "not integrated"):
                execute(SimpleNamespace(), ["rotation-control", "publication-io"], None)
            run.assert_not_called()

    def test_profile_does_not_inherit_old_faults_or_genesis(self):
        template = {
            "schema": 1,
            "cpp_revision": "reference",
            "global_version": 16,
            "consensus": {},
            "auth_network_tag": "tag",
            "observer_budget": {},
            "genesis_time": 123,
            "expected_zerostate": {"old": True},
        }
        profile = make_profile("necessary-low-weight-mixed", template, 500)
        self.assertNotIn("observer_budget", profile)
        self.assertEqual(profile["genesis_time"], 500)
        self.assertIsNone(profile["expected_zerostate"])
        self.assertEqual(
            profile["initial_weights"], {"0": 29, "1": 11, "2": 10, "3": 10}
        )
        self.assertEqual(profile["initial_probe_pause"], [1])
        self.assertEqual(profile["weighted_quorum_pause"], [0, 2])

    def test_base_rotation_does_not_claim_all_signers(self):
        result = rotation_result()
        for epoch in result["epochs"].values():
            epoch.pop("mc_signers")
        check_result("rotation-mixed", result)
        result["weighted_quorum"] = weighted_receipt()
        with self.assertRaises(ValueError):
            check_result("exact-weight-mixed", result)

    def test_zero_exit_does_not_replace_result(self):
        with self.assertRaises(ValueError):
            check_result("rotation-mixed", {"exit_code": 0})

    def test_mode_and_full_epochs_required(self):
        result = rotation_result()
        check_result("rotation-mixed", result)
        changes = [
            lambda r: r.update(status="cpp_membership_rotation_observed"),
            lambda r: r.update(all_six_applied_mc_states_match=False),
            lambda r: r.update(independent_post_rotation_finality_qualified=False),
            lambda r: r["epochs"]["after"]["wc_creators"].pop(0),
        ]
        for mutate in changes:
            changed = copy.deepcopy(result)
            mutate(changed)
            with self.assertRaises(ValueError):
                check_result("rotation-mixed", changed)

    def test_exact_weight_cannot_be_omitted_or_changed(self):
        result = rotation_result()
        with self.assertRaises(ValueError):
            check_result("exact-weight-mixed", result)
        result["weighted_quorum"] = weighted_receipt()
        check_result("exact-weight-mixed", result)
        for key, value in [
            ("surviving_weight", 41),
            ("quorum_weight", 41),
            ("survivor_members", [0, 5]),
            ("same_processes", False),
            ("manual_database_repair", True),
            ("phase", "paused"),
        ]:
            changed = copy.deepcopy(result)
            changed["weighted_quorum"][key] = value
            with self.assertRaises(ValueError):
                check_result("exact-weight-mixed", changed)
        with self.assertRaises(ValueError):
            check_result("rotation-mixed", result)

    def test_initial_probe_is_additional_requirement(self):
        result = rotation_result()
        result["weighted_quorum"] = weighted_receipt()
        with self.assertRaises(ValueError):
            check_result("necessary-low-weight-mixed", result)
        result["initial_probe"] = weighted_receipt(49, [0, 2, 3])
        check_result("necessary-low-weight-mixed", result)

    def test_restart_requires_requested_identity_and_own_participation(self):
        result = rotation_result()
        result["recovery"] = {
            "member": 5,
            "phase": "recovered",
            "interruption_returncode": -9,
            "manual_database_repair": False,
            "all_six_applied_states_match": True,
            "successor_finality_checked": True,
            "workchain_states_match": True,
            "vote": {"block": "verified"},
            "leaders": {"masterchain": {}, "workchain": {}},
        }
        check_result("restart-member5", result)
        with self.assertRaises(ValueError):
            check_result("restart-member2", result)
        result["recovery"].pop("vote")
        with self.assertRaises(ValueError):
            check_result("restart-member5", result)


if __name__ == "__main__":
    unittest.main()
