"""Matrix adapter boundary, weighted-quorum and negative-observation tests."""

import copy
import unittest
from pathlib import Path
from types import SimpleNamespace

from scenario_matrix import (
    MATRICES,
    check_matrix_result,
    make_matrix_profile,
    matrix_commands,
    member_id,
)

TEMPLATE = {
    "schema": 1,
    "cpp_revision": "reference",
    "global_version": 16,
    "consensus": {},
    "auth_network_tag": "tag",
}


def healthy(name):
    count, cpp, _ = MATRICES[name]
    return {
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
        "creators": {member_id(i): {} for i in range(count)},
        "workchain_creators": {member_id(i): {} for i in range(count)},
        "common_state_checkpoints": 2,
        "workchain_state_checkpoints": 2,
    }


def threshold():
    name = "matrix3-threshold-mixed"
    profile = make_matrix_profile(name, TEMPLATE, 500)
    result = healthy(name)
    result["threshold_fault"] = {
        "phase": "recovered",
        "plan": profile["threshold_fault"],
        "validator_count": 3,
        "total_weight": 51,
        "quorum_weight": 34,
        "survivor_members": [0, 1],
        "below_quorum_members": [0],
        "below_quorum_weight": 17,
        "positive_kind": "exact_quorum",
        "same_processes": True,
        "manual_database_repair": False,
        "all_declared_mc_states_match": True,
        "all_declared_wc_states_match": True,
        "observation_elapsed_seconds": 12.1,
        "observation_count": 45,
        "below_baseline": {"0": {"last": {"seqno": 10}, "state_root_hash": "hash"}},
        "below_final_references": {
            "0": {"last": {"seqno": 10}, "state_root_hash": "hash"}
        },
        "votes": {"1": {}, "2": {}},
        "leaders": {i: {"masterchain": {}, "workchain": {}} for i in ["1", "2"]},
        "survivor_certificates": [
            {
                "validator_ids": [member_id(0), member_id(1)],
                "verified_weight": 34,
                "final_certificate_checked": True,
            }
        ],
    }
    return name, profile, result


class MatrixAdapterTest(unittest.TestCase):
    def test_all_fixed_profiles_and_healthy_receipts(self):
        for name, (_, _, variant) in MATRICES.items():
            with self.subTest(name=name):
                profile = make_matrix_profile(name, TEMPLATE, 500)
                self.assertIsNone(profile["expected_zerostate"])
                self.assertEqual(profile["genesis_time"], 500)
                if variant == "healthy":
                    check_matrix_result(name, healthy(name), profile)

    def test_history_flags_and_budget(self):
        args = SimpleNamespace(
            cpp_python="venv/python",
            snapshot="snapshot",
            rust_node="rtos",
            validator_preparer="prepare",
            block_checker="check",
            rust_revision="rev",
        )
        for name, (count, cpp, _) in MATRICES.items():
            prepare, run = matrix_commands(args, name, Path("fresh"))
            self.assertEqual(run[run.index("--timeout") + 1], "180")
            self.assertEqual(
                "--workchain-creator-history" in run, count == 4 and cpp > 0
            )
            self.assertIn("--verify-certificates", run)
            self.assertIn("--verify-workchain", run)
            self.assertIn("--prepare-genesis-only", prepare)
            self.assertNotIn("--recovery-timeout", run)

    def test_threshold_receipt_mutations(self):
        name, profile, result = threshold()
        check_matrix_result(name, result, profile)
        mutations = [
            lambda f: f.update(observation_elapsed_seconds=11.9),
            lambda f: f.update(observation_count=0),
            lambda f: f.update(same_processes=False),
            lambda f: f.update(manual_database_repair=True),
            lambda f: f.update(survivor_certificates=[]),
            lambda f: f["survivor_certificates"][0].update(verified_weight=33),
            lambda f: f["below_final_references"]["0"].update(
                state_root_hash="different"
            ),
            lambda f: f["below_final_references"]["0"]["last"].update(seqno=11),
            lambda f: f["votes"].pop("2"),
            lambda f: f["leaders"]["2"].pop("workchain"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                changed = copy.deepcopy(result)
                mutate(changed["threshold_fault"])
                with self.assertRaises(ValueError):
                    check_matrix_result(name, changed, profile)

    def test_six_member_threshold_and_weighted_receipts(self):
        for variant in ("threshold", "low-weight-majority"):
            name = f"matrix6-{variant}-mixed"
            profile = make_matrix_profile(name, TEMPLATE, 500)
            result = healthy(name)
            _, _, sample = threshold()
            fault = copy.deepcopy(sample["threshold_fault"])
            weighted = variant == "low-weight-majority"
            survivors = list(range(6)) if weighted else [0, 2, 3, 4]
            below = list(range(5)) if weighted else [0, 2, 4]
            restored = [5] if weighted else [1, 3, 5]
            fault.update(
                plan=profile["threshold_fault"],
                validator_count=6,
                total_weight=60 if weighted else 102,
                quorum_weight=40 if weighted else 68,
                survivor_members=survivors,
                below_quorum_members=below,
                below_quorum_weight=30 if weighted else 51,
                positive_kind="high_weight_required" if weighted else "exact_quorum",
                below_baseline={
                    str(i): {"last": {"seqno": 10}, "state_root_hash": "hash"}
                    for i in below
                },
                below_final_references={
                    str(i): {"last": {"seqno": 10}, "state_root_hash": "hash"}
                    for i in below
                },
                votes={str(i): {} for i in restored},
                leaders={
                    str(i): {"masterchain": {}, "workchain": {}} for i in restored
                },
                survivor_certificates=[
                    {
                        "validator_ids": [member_id(i) for i in survivors],
                        "verified_weight": 60 if weighted else 68,
                        "final_certificate_checked": True,
                    }
                ],
            )
            result["threshold_fault"] = fault
            check_matrix_result(name, result, profile)
            fault["survivor_certificates"][0]["validator_ids"].pop()
            with self.assertRaises(ValueError):
                check_matrix_result(name, result, profile)

    def test_no_height_only_or_wrong_identity_pass(self):
        name = "matrix4-cpp2"
        profile = make_matrix_profile(name, TEMPLATE, 500)
        mutations = [
            lambda r: r.update(final_certificates_required=False),
            lambda r: r.update(workchain_states_required=False),
            lambda r: r.update(workchain_state_checkpoints=0),
            lambda r: r["workchain_creators"].pop(member_id(2)),
            lambda r: r["creators"].update(unknown=r["creators"].pop(member_id(2))),
            lambda r: r.update(cpp_count=3),
        ]
        for mutate in mutations:
            result = healthy(name)
            mutate(result)
            with self.assertRaises(ValueError):
                check_matrix_result(name, result, profile)


if __name__ == "__main__":
    unittest.main()
