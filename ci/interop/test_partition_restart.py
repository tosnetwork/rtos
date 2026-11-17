#!/usr/bin/env python3
"""Hermetic lifecycle checks; real packet enforcement is a separate fixture gate."""

import copy
import json
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import partition_restart_fixture as combined
import rotation_fixture as rotation


class FakeFault:
    def __init__(self, *args):
        self.owned = False
        self.drops = 0
        self.restores = 0

    def arm(self):
        self.owned = True
        self.armed_at = time.time()

    def statistics(self):
        self.drops += 10
        return {"drops": self.drops, "packets": self.drops}

    def restore(self):
        self.owned = False
        self.restores += 1


class PartitionRestartTests(unittest.IsolatedAsyncioTestCase):
    def context(self, root, *, original_budget=None):
        directory = root / "node"
        directory.mkdir()
        (directory / "default_config.json").write_text(
            json.dumps(
                {
                    "ip_address": "127.0.0.1:10001",
                    "ip_address_quic": "127.0.0.1:10002",
                    "json_rpc_server": {"address": "127.0.0.1:10003"},
                    "lite_server_port": 10004,
                }
            )
        )
        args = SimpleNamespace(
            network_fault_seconds=0.001,
            socket_mark_library=Path("mark.so"),
            interrupt_rust_member=2,
            recovery_timeout=5,
            original_recovery_budget=original_budget,
        )
        node = {
            "directory": directory,
            "process": SimpleNamespace(pid=10, returncode=None),
        }
        with patch.object(combined, "PacketFault", FakeFault):
            context = combined.PartitionRestart(
                args, root, node, "http://127.0.0.1:10003", str
            )
        return context, node

    def test_expiry_partition_keeps_original_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            start = time.monotonic() - 2
            context, _ = self.context(
                Path(tmp), original_budget={"monotonic": start, "unix": 100.0}
            )
            self.assertEqual(context.started, start)
            self.assertEqual(context.deadline, start + 5)
            self.assertEqual(context.receipt["budget_started_at_unix"], 100.0)
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(TimeoutError):
            self.context(
                Path(tmp),
                original_budget={"monotonic": time.monotonic() - 10, "unix": 100.0},
            )

    def proof(self):
        return {
            "block": {"seqno": 12},
            "configuration": {
                "current": {
                    "members": [
                        {"validator_id": str(i), "weight": 17} for i in [0, 2, 4, 5]
                    ]
                }
            },
            "verified_final_certificates": [
                {"validator_ids": ["0", "4", "5"], "verified_weight": 51}
            ],
        }

    async def test_partition_covers_restarted_process_until_restoration(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, old = self.context(Path(tmp))
            await context.arm()
            old["process"].returncode = -9
            await context.after_interruption()
            context.survivor(self.proof())
            new = {
                "process": SimpleNamespace(pid=20, returncode=None),
                "start_ticks": "777",
            }
            with (
                patch.object(Path, "read_text", return_value="0 " * 21 + "777"),
                patch.object(combined, "rpc", side_effect=TimeoutError("partition")),
            ):
                await context.after_restart(new)
            for key in ("kernel_before_restart_hold", "kernel_after_restart_hold"):
                sample = json.loads((context.directory / f"{key}.json").read_text())
                self.assertEqual(sample, context.receipt[key])
            self.assertFalse(context.fault.owned)
            self.assertEqual(context.fault.restores, 1)
            self.assertEqual(context.receipt["new_pid"], 20)
            self.assertTrue(context.receipt["isolated_rpc_timeout_observed"])
            self.assertGreater(
                context.receipt["kernel_after_restart_hold"]["drops"],
                context.receipt["kernel_before_restart_hold"]["drops"],
            )
            await context.complete(
                {"last_checkpoint": {"seqno": 15}, "manual_database_repair": False}
            )
            context.close()
            self.assertEqual(context.receipt["phase"], "recovered")
            self.assertEqual(context.fault.restores, 1)

    async def test_original_budget_is_not_extended_by_hold(self):
        started = time.monotonic()
        checks = []
        with self.assertRaisesRegex(TimeoutError, "original recovery deadline"):
            await combined.hold(0.2, started + 0.01, lambda: checks.append(True))
        self.assertTrue(checks)
        self.assertLess(time.monotonic() - started, 0.15)

    async def test_connection_refusal_is_not_counted_as_packet_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, _ = self.context(Path(tmp))
            await context.arm()
            new = {
                "process": SimpleNamespace(pid=20, returncode=None),
                "start_ticks": "777",
            }
            with (
                patch.object(Path, "read_text", return_value="0 " * 21 + "777"),
                patch.object(
                    combined,
                    "rpc",
                    side_effect=urllib.error.URLError(ConnectionRefusedError()),
                ),
                self.assertRaises(urllib.error.URLError),
            ):
                await context.after_restart(new)
            context.close()
            self.assertNotIn("isolated_rpc_timeout_observed", context.receipt)
            self.assertFalse(context.fault.owned)

    async def test_missing_kernel_drops_cannot_pass_and_cleanup_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, _ = self.context(Path(tmp))
            await context.arm()
            new = {
                "process": SimpleNamespace(pid=20, returncode=None),
                "start_ticks": "777",
            }
            with (
                patch.object(Path, "read_text", return_value="0 " * 21 + "777"),
                patch.object(combined, "rpc", side_effect=TimeoutError("partition")),
                patch.object(context.fault, "statistics", return_value={"drops": 0}),
                self.assertRaisesRegex(RuntimeError, "after process restart"),
            ):
                await context.after_restart(new)
            context.close()
            self.assertFalse(context.fault.owned)
            self.assertEqual(context.fault.restores, 1)

    async def test_survivor_proof_requires_original_committee_and_exact_quorum(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, _ = self.context(Path(tmp))
            good = self.proof()
            context.survivor(good)
            bad = copy.deepcopy(good)
            bad["verified_final_certificates"][0]["validator_ids"] = ["0", "2", "4"]
            with self.assertRaisesRegex(RuntimeError, "exactly the surviving quorum"):
                context.survivor(bad)
            self.assertEqual(context.receipt["total_weight"], 68)
            self.assertEqual(context.receipt["surviving_weight"], 51)

    async def test_below_quorum_uses_historical_checkpoint_without_claiming_new_survivor_certificate(
        self,
    ):
        from recovery_quorum_fixture import recovery_quorum_plan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context, _ = self.context(root)
            context.below_quorum = True
            context.quorum_plan = recovery_quorum_plan(
                {"successor_weights": {"0": 10, "2": 30, "4": 10, "5": 10}}, 2, True
            )
            proof = self.proof()
            proof["state_root_hash"] = "state"
            for entry in proof["configuration"]["current"]["members"]:
                entry["weight"] = context.quorum_plan["weights"][
                    int(entry["validator_id"])
                ]
            proof["verified_final_certificates"] = [
                {"validator_ids": ["0", "2", "4"], "verified_weight": 50}
            ]
            d = root / "recovery-quorum"
            d.mkdir()
            observation = {
                "phase": "observed_no_finality",
                "plan": context.quorum_plan,
                "block": proof["block"],
                "state_root_hash": "state",
                "observation_count": 60,
                "observation_elapsed_seconds": 12.1,
                "required_observe_seconds": 12,
            }
            # Real IDs include complete hashes; identity compares all fields.
            proof["block"].update(
                workchain=-1,
                shard="-9223372036854775808",
                root_hash="root",
                file_hash="file",
            )
            (d / "receipt.json").write_text(json.dumps(observation))
            context.survivor(proof)
            self.assertEqual(context.receipt["surviving_weight"], 30)
            self.assertEqual(context.receipt["quorum_weight"], 40)
            self.assertNotIn("survivor_certificates", context.receipt)
            self.assertEqual(
                context.receipt["survivor_kind"],
                "historical_checkpoint_after_below_quorum_stall",
            )
            context.close()

    async def test_plain_recovery_does_not_create_packet_fault(self):
        async def plain(*args):
            return {"phase": "recovered"}, None

        with (
            patch.object(rotation, "_recover_rotation_member", plain),
            patch.object(
                combined,
                "PartitionRestart",
                side_effect=AssertionError("unexpected packet fault"),
            ),
        ):
            result = await rotation.recover_rotation_member(
                SimpleNamespace(), None, [], [], [], [], None, None, None, {}
            )
        self.assertEqual(result["phase"], "recovered")

    async def test_wrapper_restores_partition_after_recovery_failure(self):
        closed = []

        class Context:
            def __init__(self, *args):
                pass

            def close(self):
                closed.append(True)

        async def fail(*args):
            raise RuntimeError("owned fixture failure")

        with (
            patch.object(rotation, "_recover_rotation_member", fail),
            patch.object(combined, "PartitionRestart", Context),
            self.assertRaisesRegex(RuntimeError, "owned fixture failure"),
        ):
            await rotation.recover_rotation_member(
                SimpleNamespace(partition_restart=True, interrupt_rust_member=2),
                None,
                [],
                [None] * 6,
                [],
                [{"index": 2}],
                None,
                None,
                None,
                {},
            )
        self.assertEqual(closed, [True])


if __name__ == "__main__":
    unittest.main()
