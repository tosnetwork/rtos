"""Reject misleading restart, packet-counter and weighted-stall receipts."""

import copy
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scenario_matrix import member_id
from scenario_restart import (
    check_restart_cleanup,
    check_restart_partition,
    restart_arguments,
)


def fixture(member=2, below=False):
    block = {"seqno": 10, "root_hash": "a"}
    final = {"seqno": 20, "root_hash": "b"}
    recovery = {
        "member": member,
        "phase": "recovered",
        "interruption_returncode": -9,
        "manual_database_repair": False,
        "all_six_applied_states_match": True,
        "successor_finality_checked": True,
        "workchain_states_match": True,
        "old_process": {"pid": 10, "start_ticks": "100"},
        "new_process": {"pid": 20, "start_ticks": "200"},
        "survivor_checkpoint": block,
        "last_checkpoint": final,
        "vote": {"sample_directory": "vote"},
        "leaders": {"masterchain": {}, "workchain": {}},
    }
    receipt = {
        "member": member,
        "phase": "recovered",
        "mode": "partition_during_original_database_restart",
        "settle_after_interruption_seconds": 12,
        "hold_after_restart_seconds": 12,
        "recovery_limit_seconds": 180,
        "interruption_returncode": -9,
        "isolated_rpc_timeout_observed": True,
        "manual_database_repair": False,
        "elapsed_seconds": 45,
        "old_pid": 10,
        "new_pid": 20,
        "new_start_ticks": "200",
        "armed_at_unix": 100,
        "restarted_at_unix": 120,
        "restored_at_unix": 133,
        "kernel_before_restart_hold": {"kind": "netem", "handle": "30:", "drops": 100},
        "kernel_after_restart_hold": {"kind": "netem", "handle": "30:", "drops": 120},
        "survivor_checkpoint": block,
        "final_checkpoint": final,
        "surviving_weight": 51,
        "total_weight": 68,
        "survivor_certificates": [
            {
                "final_certificate_checked": True,
                "validator_ids": [member_id(i) for i in (0, 2, 4, 5) if i != member],
                "verified_weight": 51,
            }
        ],
    }
    if below:
        receipt.pop("survivor_certificates")
        receipt.update(
            survivor_kind="historical_checkpoint_after_below_quorum_stall",
            surviving_weight=30,
            total_weight=60,
            quorum_weight=40,
            below_quorum_observation={
                "phase": "observed_no_finality",
                "required_observe_seconds": 12,
                "manual_database_repair": False,
                "observation_count": 60,
                "observation_elapsed_seconds": 12.1,
                "block": block,
                "state_root_hash": "state",
                "plan": {
                    "member": 2,
                    "weights": {"0": 10, "2": 30, "4": 10, "5": 10},
                    "total_weight": 60,
                    "quorum_weight": 40,
                    "surviving_weight": 30,
                    "survivor_members": [0, 4, 5],
                    "live_endpoints": [0, 1, 3, 4, 5],
                    "settle_seconds": 4,
                    "observe_seconds": 12,
                },
            },
        )
    return receipt, recovery


class RestartTests(unittest.TestCase):
    def test_adapter_selects_fixed_weight_and_refuses_unrequested_partition(self):
        from scenario_execution import check_result, make_profile
        from test_scenario_execution import rotation_result

        template = {
            "schema": 1,
            "cpp_revision": "reference",
            "global_version": 16,
            "consensus": {},
            "auth_network_tag": "tag",
        }
        profile = make_profile("below-quorum-restart", template, 100)
        self.assertEqual(
            profile["successor_weights"], {"0": 10, "2": 30, "4": 10, "5": 10}
        )
        for name, member in (
            ("partition-restart-member2", 2),
            ("partition-restart-member5", 5),
            ("below-quorum-restart", 2),
        ):
            result = rotation_result()
            result["partition_restart"], result["recovery"] = fixture(
                member, name == "below-quorum-restart"
            )
            check_result(name, result)
            with self.assertRaises(ValueError):
                check_result("rotation-mixed", result)
            result["recovery"]["workchain_states_match"] = False
            with self.assertRaises(ValueError):
                check_result(name, result)

    def test_real_driver_duration_numbers(self):
        for name, member in (
            ("partition-restart-member2", 2),
            ("partition-restart-member5", 5),
            ("below-quorum-restart", 2),
        ):
            receipt, recovery = fixture(member, name == "below-quorum-restart")
            for field in (
                "settle_after_interruption_seconds",
                "hold_after_restart_seconds",
                "recovery_limit_seconds",
            ):
                receipt[field] = float(receipt[field])
            check_restart_partition(name, receipt, recovery)
            for field, expected in (
                ("settle_after_interruption_seconds", 12),
                ("hold_after_restart_seconds", 12),
                ("recovery_limit_seconds", 180),
            ):
                for invalid in (
                    True,
                    str(expected),
                    None,
                    expected + 0.5,
                    float("nan"),
                    float("inf"),
                ):
                    altered = copy.deepcopy(receipt)
                    altered[field] = invalid
                    with self.assertRaises(
                        ValueError, msg=f"{name}: {field}={invalid}"
                    ):
                        check_restart_partition(name, altered, recovery)

    def test_fixed_modes_and_necessary_member(self):
        for name, member in (
            ("partition-restart-member2", 2),
            ("partition-restart-member5", 5),
            ("below-quorum-restart", 2),
        ):
            below = name == "below-quorum-restart"
            check_restart_partition(name, *fixture(member, below))
            args = restart_arguments(name, "/native/mark.so")
            self.assertEqual(
                args[args.index("--interrupt-rust-member") + 1], str(member)
            )
            self.assertEqual("--recovery-below-quorum" in args, below)
            self.assertIn("--partition-restart", args)

    def test_old_process_counter_cannot_prove_new_process_partition(self):
        for change in (
            lambda p, r: p.update(new_pid=10),
            lambda p, r: p.update(new_start_ticks="other"),
            lambda p, r: p["kernel_after_restart_hold"].update(drops=100),
            lambda p, r: p.update(restored_at_unix=131),
            lambda p, r: p.update(isolated_rpc_timeout_observed=False),
            lambda p, r: p.update(elapsed_seconds=181),
            lambda p, r: r["leaders"].pop("workchain"),
            lambda p, r: r.update(manual_database_repair=True),
            lambda p, r: p.update(final_checkpoint={"seqno": 20, "root_hash": "fork"}),
            lambda p, r: p["survivor_certificates"][0]["validator_ids"].__setitem__(
                0, member_id(2)
            ),
        ):
            p, r = fixture()
            change(p, r)
            with self.assertRaises(ValueError):
                check_restart_partition("partition-restart-member2", p, r)

    def test_counting_endpoints_or_historical_quorum_as_live_weight_refused(self):
        original, recovery = fixture(below=True)
        for change in (
            lambda p: p.update(surviving_weight=40),
            lambda p: p["below_quorum_observation"].update(
                observation_elapsed_seconds=11.9
            ),
            lambda p: p["below_quorum_observation"].update(block={"seqno": 11}),
            lambda p: p["below_quorum_observation"]["plan"].update(
                survivor_members=[0, 1, 3, 4, 5]
            ),
            lambda p: p["below_quorum_observation"]["plan"]["weights"].update(
                {"2": 10}
            ),
        ):
            receipt = copy.deepcopy(original)
            change(receipt)
            with self.assertRaises(ValueError):
                check_restart_partition("below-quorum-restart", receipt, recovery)

    def test_cleanup_requires_isolation_and_native_counter_binding(self):
        receipt, _ = fixture()
        injection = {
            "mode": "partition",
            "owned_qdisc": False,
            "namespace": {
                "network": "child-net",
                "parent_network": "parent-net",
                "user": "child-user",
                "parent_user": "parent-user",
            },
        }
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "recovery-partition/injection"
            target.mkdir(parents=True)
            stats = [receipt["kernel_after_restart_hold"]]
            for key in ("kernel_before_restart_hold", "kernel_after_restart_hold"):
                (target.parent / f"{key}.json").write_text(json.dumps(receipt[key]))
            (target / "statistics.json").write_text(json.dumps(stats))
            (target / "injection.json").write_text(json.dumps(injection))
            check_restart_cleanup(root, receipt)
            for change in (
                lambda value: value.update(owned_qdisc=True),
                lambda value: value["namespace"].update(network="parent-net"),
                lambda value: value["namespace"].update(user="parent-user"),
            ):
                changed = copy.deepcopy(injection)
                change(changed)
                (target / "injection.json").write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    check_restart_cleanup(root, receipt)
            (target / "injection.json").write_text(json.dumps(injection))
            for key in ("kernel_before_restart_hold", "kernel_after_restart_hold"):
                sample = target.parent / f"{key}.json"
                original = sample.read_bytes()
                sample.write_text(json.dumps({"drops": -1}))
                with self.assertRaises(ValueError):
                    check_restart_cleanup(root, receipt)
                sample.unlink()
                with self.assertRaises(FileNotFoundError):
                    check_restart_cleanup(root, receipt)
                sample.write_bytes(original)
            (target / "statistics.json").write_text(json.dumps([]))
            with self.assertRaises(ValueError):
                check_restart_cleanup(root, receipt)


if __name__ == "__main__":
    unittest.main()
