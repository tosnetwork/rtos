"""Combined scenarios must bind both faults to the same process and budget."""

import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scenario_ack_partition import ack_partition_arguments, check_ack_partition_result
from scenario_execution import check_result
from test_scenario_ack import fixture as ack_fixture
from test_scenario_execution import rotation_result
from test_scenario_restart import fixture as restart_fixture


def fixture(root, mode):
    source, _ = ack_fixture(root, mode)
    partition, recovery = restart_fixture()
    source.update(
        survivor_checkpoint=partition["survivor_checkpoint"],
        final_checkpoint=partition["final_checkpoint"],
        budget_started_at_unix=90.0,
        native_error_observed_at_unix=95.0,
        recovery_limit_seconds=180.0,
        elapsed_seconds=45.0,
    )
    partition["budget_started_at_unix"] = 90.0
    combined = {
        "phase": "recovered",
        "member": 2,
        "mode": "source_ack_failure_and_partition_across_restart",
        "source_ack_fault": mode,
        "source_phase": "recovered",
        "partition_phase": "recovered",
        "source_fault_removed_before_restart": True,
        "original_source_ack_recovered": True,
        "isolated_rpc_timeout_observed": True,
        "manual_database_repair": False,
        "recovery_limit_seconds": 180.0,
        "hold_before_survivor_seconds": 12.0,
        "hold_after_restart_seconds": 12.0,
        "budget_started_at_unix": 90.0,
        "elapsed_seconds": 46.0,
        "native_error_observed_at_unix": 95.0,
        "partition_armed_at_unix": 100,
        "restored_at_unix": 133,
        "survivor_checkpoint": partition["survivor_checkpoint"],
        "final_checkpoint": partition["final_checkpoint"],
    }
    return combined, source, partition, recovery


class AckPartitionTests(unittest.TestCase):
    def test_both_modes_bind_components_and_fixed_arguments(self):
        for mode in ("sync-eio", "write-enospc"):
            with TemporaryDirectory() as directory:
                name = "source-ack-partition-" + mode
                receipts = fixture(Path(directory), mode)
                check_ack_partition_result(name, *receipts)
                result = rotation_result()
                for key, value in zip(
                    (
                        "source_ack_partition_restart",
                        "source_ack_fault",
                        "partition_restart",
                        "recovery",
                    ),
                    receipts,
                ):
                    result[key] = value
                check_result(name, result)
                args = ack_partition_arguments(name, "/ack.so", "/packet.so")
                self.assertEqual(args.count("--interrupt-rust-member"), 1)
                self.assertEqual(args[args.index("--source-ack-fault") + 1], mode)
                self.assertIn("--partition-restart", args)
                self.assertIn("--source-ack-partition-restart", args)
                with self.assertRaises(ValueError):
                    check_result("source-ack-" + mode, result)

    def test_mixed_budgets_phases_processes_and_extra_cuts_refused(self):
        with TemporaryDirectory() as directory:
            original = fixture(Path(directory), "sync-eio")
            changes = (
                lambda c, s, p, r: c.update(source_phase="prepared"),
                lambda c, s, p, r: c.update(source_fault_removed_before_restart=False),
                lambda c, s, p, r: s.update(budget_started_at_unix=91),
                lambda c, s, p, r: p.update(budget_started_at_unix=89),
                lambda c, s, p, r: c.update(recovery_limit_seconds=181),
                lambda c, s, p, r: c.update(hold_after_restart_seconds=True),
                lambda c, s, p, r: c.update(elapsed_seconds=float("nan")),
                lambda c, s, p, r: s.update(native_error_observed_at_unix=101),
                lambda c, s, p, r: c.update(partition_armed_at_unix=99),
                lambda c, s, p, r: c.update(final_checkpoint={"seqno": 999}),
                lambda c, s, p, r: s.update(new_pid=30),
                lambda c, s, p, r: c.update(intent_cut={}),
                lambda c, s, p, r: c.update(cold_bootstrap_body={}),
            )
            for change in changes:
                receipts = copy.deepcopy(original)
                change(*receipts)
                with self.assertRaises(ValueError):
                    check_ack_partition_result(
                        "source-ack-partition-sync-eio", *receipts
                    )
