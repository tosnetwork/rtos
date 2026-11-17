"""Composition gates; native IO and kernel packet gates remain actual-run requirements."""

import asyncio
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import partition_restart_fixture as partition
import source_ack_fault_fixture as source
import source_ack_partition_fixture as combined
import test_source_ack_fault as source_tests
from test_partition_restart import FakeFault


class SourceAckPartitionTests(unittest.IsolatedAsyncioTestCase):
    def context(self, root):
        helper = source_tests.SourceAckTests()
        _, node, pending = helper.context(root)
        (node["directory"] / "default_config.json").write_text(
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
            source_ack_fault="sync-eio",
            recovery_timeout=2,
            interrupt_rust_member=2,
            network_fault_seconds=0.001,
            socket_mark_library=Path("/socket-mark.so"),
        )
        checkpoint = {
            "gen_catchain_seqno": 1,
            "verified_final_certificates": [
                {"session_id": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="}
            ],
        }
        with patch.object(partition, "PacketFault", FakeFault):
            context = combined.SourceAckPartitionRestart(
                args, root, node, "http://owned", str, checkpoint
            )
        return context, node, pending, helper

    async def test_lifecycle_requires_both_source_ack_and_restarted_packet_isolation(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            context, node, pending, helper = self.context(Path(tmp))

            async def observe_native():
                helper.captured(context.source, node, pending)

            with patch.object(context.source, "arm", observe_native):
                await context.arm()
            self.assertLessEqual(
                context.receipt["native_error_observed_at_unix"],
                context.receipt["partition_armed_at_unix"],
            )
            self.assertEqual(context.deadline, context.source.deadline)
            self.assertEqual(context.deadline, context.partition.deadline)
            self.assertEqual(context.source.started, context.partition.started)
            node["process"].returncode = -9
            with patch.object(source, "hold", AsyncMock()):
                await context.after_interruption()
            proof = {
                "block": {"seqno": 10},
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
            context.survivor(proof)
            with patch.object(
                partition,
                "marked_environment",
                return_value={"LD_PRELOAD": "/socket-mark.so"},
            ):
                env = context.environment()
            self.assertEqual(env, {"LD_PRELOAD": "/socket-mark.so"})
            self.assertFalse((context.source.directory / "armed").exists())
            new = {
                "process": SimpleNamespace(pid=20, returncode=None),
                "start_ticks": "777",
            }
            node.update(new)
            with (
                patch.object(Path, "read_text", return_value="0 " * 21 + "777"),
                patch.object(partition, "rpc", side_effect=TimeoutError("partition")),
            ):
                await context.after_restart(node)
            self.assertTrue(context.partition.receipt["isolated_rpc_timeout_observed"])
            # Consensus recovery by itself cannot satisfy the combined gate.
            self.assertNotEqual(context.receipt["phase"], "recovered")
            name = context.source.source_id
            original = context.source.original
            refs = pending / "references-v1"
            refs.mkdir()
            (refs / (name + ".reference")).write_text(
                json.dumps(
                    {
                        "digest": hashlib.sha256(original).hexdigest(),
                        "metadata": {
                            **json.loads(original),
                            "data": "",
                            "signature_set": "",
                        },
                        "node_receipt": "b" * 64,
                    }
                )
            )
            context.source.pending.unlink()
            await context.complete(
                {"last_checkpoint": {"seqno": 18}, "manual_database_repair": False}
            )
            context.close()
            self.assertEqual(context.receipt["phase"], "recovered")
            self.assertTrue(context.receipt["original_source_ack_recovered"])
            self.assertTrue(context.receipt["isolated_rpc_timeout_observed"])
            self.assertEqual(context.partition.fault.restores, 1)

    async def test_restart_environment_cannot_keep_source_fault_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, node, pending, helper = self.context(Path(tmp))
            helper.captured(context.source, node, pending)
            with (
                patch.object(
                    partition,
                    "marked_environment",
                    return_value={"RTOS_TEST_SOURCE_FAULT_MODE": "sync-eio"},
                ),
                self.assertRaisesRegex(RuntimeError, "inherited source IO fault"),
            ):
                context.environment()
            context.close()

    async def test_missing_original_ack_cannot_be_replaced_by_consensus_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, node, pending, helper = self.context(Path(tmp))
            helper.captured(context.source, node, pending)
            context.source.deadline = context.deadline = context.partition.deadline = (
                time.monotonic() + 0.01
            )
            with self.assertRaisesRegex(TimeoutError, "original recovery deadline"):
                await context.complete(
                    {"last_checkpoint": {"seqno": 18}, "manual_database_repair": False}
                )
            self.assertNotEqual(context.receipt["phase"], "recovered")
            context.close()

    async def test_failed_arm_never_installs_partition_before_native_ack_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, _, _, _ = self.context(Path(tmp))
            with (
                patch.object(
                    context.source,
                    "arm",
                    AsyncMock(side_effect=RuntimeError("native gate")),
                ),
                self.assertRaisesRegex(RuntimeError, "native gate"),
            ):
                await context.arm()
            self.assertFalse(context.partition.fault.owned)
            context.close()

    async def test_close_restores_partition_even_when_source_cleanup_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, _, _, _ = self.context(Path(tmp))
            await context.partition.arm()
            with (
                patch.object(
                    context.source, "close", side_effect=RuntimeError("source cleanup")
                ),
                self.assertRaisesRegex(RuntimeError, "source cleanup"),
            ):
                context.close()
            self.assertFalse(context.partition.fault.owned)
            self.assertEqual(context.partition.fault.restores, 1)

    async def test_failed_parallel_hold_cancels_and_joins_sibling(self):
        owned = asyncio.Event()
        closed = []

        async def sibling():
            try:
                owned.set()
                await asyncio.Event().wait()
            finally:
                closed.append(True)

        async def fail():
            await owned.wait()
            raise RuntimeError("failed hold")

        with self.assertRaisesRegex(RuntimeError, "failed hold"):
            await combined.join_owned(sibling(), fail())
        self.assertEqual(closed, [True])

    async def test_initial_environment_loads_both_libraries_without_losing_mark_or_io_settings(
        self,
    ):
        args = SimpleNamespace(socket_mark_library=Path("/mark.so"))
        with (
            patch.object(
                combined,
                "source_ack_environment",
                return_value={
                    "LD_PRELOAD": "/io.so",
                    "RTOS_TEST_SOURCE_FAULT_MODE": "sync-eio",
                },
            ),
            patch.object(
                combined,
                "marked_environment",
                return_value={
                    "LD_PRELOAD": "/mark.so",
                    "RTOS_FIXTURE_SOCKET_MARK": "fixture-mark",
                },
            ),
        ):
            env = combined.source_ack_partition_environment(args, Path("/owned"))
        self.assertEqual(env["LD_PRELOAD"], "/io.so:/mark.so")
        self.assertEqual(env["RTOS_TEST_SOURCE_FAULT_MODE"], "sync-eio")
        self.assertEqual(env["RTOS_FIXTURE_SOCKET_MARK"], "fixture-mark")


class CompositionArgumentTests(unittest.TestCase):
    def arguments(self, extra):
        import rotation_fixture as rotation

        base = [
            "rotation_fixture.py",
            "--snapshot",
            "/snapshot",
            "--block-checker",
            "/checker",
            "--profile",
            "/profile",
            "--output",
            "/owned-output",
            "--rust-node",
            "/rust",
            "--validator-preparer",
            "/preparer",
            "--interrupt-rust-member",
            "2",
            "--source-ack-fault-library",
            "/io.so",
            "--socket-mark-library",
            "/mark.so",
        ]
        with (
            patch("sys.argv", base + extra),
            patch.object(rotation, "require_namespace"),
            patch.object(
                Path, "read_text", side_effect=RuntimeError("profile boundary")
            ),
        ):
            rotation.main()

    def test_combination_requires_explicit_opt_in(self):
        with self.assertRaisesRegex(SystemExit, "no other injected fault"):
            self.arguments(["--source-ack-fault", "sync-eio", "--partition-restart"])

    def test_opt_in_requires_both_components(self):
        for component in [["--source-ack-fault", "sync-eio"], ["--partition-restart"]]:
            with (
                self.subTest(component=component),
                self.assertRaisesRegex(SystemExit, "requires both"),
            ):
                self.arguments(["--source-ack-partition-restart"] + component)

    def test_declared_combination_refused_before_profile(self):
        with self.assertRaisesRegex(SystemExit, "awaits acceptance-path adaptation"):
            self.arguments(
                [
                    "--source-ack-partition-restart",
                    "--source-ack-fault",
                    "sync-eio",
                    "--partition-restart",
                ]
            )

    def test_intent_stop_requires_explicit_combined_ack_failure(self):
        for extra in [
            ["--source-ack-intent-stop"],
            [
                "--source-ack-intent-stop",
                "--source-ack-fault",
                "sync-eio",
                "--partition-restart",
            ],
            [
                "--source-ack-intent-stop",
                "--source-ack-partition-restart",
                "--source-ack-fault",
                "write-enospc",
            ],
            [
                "--source-ack-intent-stop",
                "--source-ack-partition-restart",
                "--partition-restart",
            ],
        ]:
            with (
                self.subTest(extra=extra),
                self.assertRaisesRegex(
                    SystemExit, "explicit source ACK fault and partition restart"
                ),
            ):
                self.arguments(extra)

    def test_intent_stop_refused_with_declared_combination(self):
        for mode in ["sync-eio", "write-enospc"]:
            with (
                self.subTest(mode=mode),
                self.assertRaisesRegex(SystemExit, "awaits acceptance-path adaptation"),
            ):
                self.arguments(
                    [
                        "--source-ack-intent-stop",
                        "--source-ack-partition-restart",
                        "--source-ack-fault",
                        mode,
                        "--partition-restart",
                    ]
                )

    def test_torn_intent_point_requires_explicit_stop_and_declared_combination(self):
        with self.assertRaisesRegex(SystemExit, "requires its explicit intent stop"):
            self.arguments(["--source-ack-intent-cut-point", "before-write"])
        for mode in ["sync-eio", "write-enospc"]:
            for point in ["before-write", "after-partial-write"]:
                with (
                    self.subTest(mode=mode, point=point),
                    self.assertRaisesRegex(
                        SystemExit, "awaits acceptance-path adaptation"
                    ),
                ):
                    self.arguments(
                        [
                            "--source-ack-intent-cut-point",
                            point,
                            "--source-ack-intent-stop",
                            "--source-ack-partition-restart",
                            "--source-ack-fault",
                            mode,
                            "--partition-restart",
                        ]
                    )


class IntentCutAdmissionTests(unittest.TestCase):
    def args(self, **overrides):
        values = {
            "source_ack_intent_stop": True,
            "source_ack_intent_cut_point": "before-write",
            "source_ack_partition_restart": True,
            "partition_restart": True,
            "source_ack_fault": "sync-eio",
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_both_native_ack_modes_keep_all_explicit_cut_points(self):
        for mode in ["sync-eio", "write-enospc"]:
            for point in ["after-fsync", "before-write", "after-partial-write"]:
                with self.subTest(mode=mode, point=point):
                    combined.validate_intent_cut(
                        self.args(
                            source_ack_fault=mode, source_ack_intent_cut_point=point
                        )
                    )

    def test_missing_composition_or_unsupported_mode_is_refused(self):
        for changes in [
            {"source_ack_partition_restart": False},
            {"partition_restart": False},
            {"source_ack_fault": None},
            {"source_ack_fault": "unsupported"},
            {"source_ack_intent_stop": False},
            {"source_ack_intent_cut_point": "unsupported"},
        ]:
            with self.subTest(changes=changes), self.assertRaises(SystemExit):
                combined.validate_intent_cut(self.args(**changes))

    def test_no_cut_keeps_ordinary_runs_unchanged(self):
        combined.validate_intent_cut(
            self.args(
                source_ack_intent_stop=False,
                source_ack_intent_cut_point="after-fsync",
                source_ack_partition_restart=False,
                partition_restart=False,
                source_ack_fault=None,
            )
        )


if __name__ == "__main__":
    unittest.main()
