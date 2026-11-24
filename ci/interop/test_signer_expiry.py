"""Expiry composition must not extend authority or restart the observation budget."""

import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import signer_expiry_fixture as expiry
import source_ack_fault_fixture as source
import test_source_ack_fault as source_tests


class SignerExpiryTests(unittest.IsolatedAsyncioTestCase):
    def args(self):
        return SimpleNamespace(
            signer_expiry_member=5,
            interrupt_rust_member=2,
            source_ack_partition_restart=False,
            partition_restart=True,
            recovery_below_quorum=True,
            source_ack_fault=None,
            recovery_timeout=2,
        )

    def test_wc_capture_pending_preserves_budget_and_routes_cleanup_to_wc(self):
        from publication_capture_arm import CaptureSessionPending

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, cp, mc = self.context(root)
            args.unsigned_original_recovery = True
            args.unsigned_workchain_originals = True
            (root / "intent-cleanup").mkdir()
            with (
                patch(
                    "publication_capture_arm.arm_capture",
                    side_effect=CaptureSessionPending("starting"),
                ),
                self.assertRaises(expiry.SignerExpiryRuntimePending),
            ):
                expiry.SignerExpiry(args, root, node, cp)
            anchor = args.signer_expiry_observation_start
            self.assertFalse((root / "signer-expiry").exists())
            wc = mc.parent / "wc/session-runtime.json"
            wc.parent.mkdir()
            wc.write_text(
                json.dumps({"session": "wc", "shard_workchain": 0, "role": "validator"})
            )

            def arm(directory, checked, control, pid):
                control.mkdir()
                (control / "arm.json").write_text(json.dumps({"runtime": str(wc)}))

            with patch("publication_capture_arm.arm_capture", side_effect=arm):
                observer = expiry.SignerExpiry(args, root, node, cp)
            self.assertEqual(args.signer_expiry_observation_start, anchor)
            self.assertEqual(observer.deadline, anchor[0] + args.recovery_timeout)
            selector = (root / "intent-cleanup/selector").read_text().splitlines()
            self.assertEqual(
                selector,
                [
                    str(node["process"].pid),
                    str(wc.parent / "finality-intents/outputs-v1"),
                ],
            )
            self.assertEqual(observer.session, bytes([4] * 32).hex())

    def test_only_explicit_equal_weight_composition_can_expire_member5(self):
        args = self.args()
        profile = {"genesis_time": 1000, "activation_delay": 90}
        self.assertEqual(expiry.expiry_plan(profile, args)["expire_at"], 1140)
        for field, value in [
            ("signer_expiry_member", 2),
            ("interrupt_rust_member", 5),
            ("recovery_below_quorum", False),
            ("source_ack_fault", "write-enospc"),
        ]:
            changed = self.args()
            setattr(changed, field, value)
            with self.assertRaises(ValueError):
                expiry.expiry_plan(profile, changed)
        with self.assertRaises(ValueError):
            expiry.expiry_plan(
                {**profile, "successor_weights": {"0": 10, "2": 30, "4": 10, "5": 10}},
                args,
            )

    def context(self, root):
        args = self.args()
        args.signer_expiry_plan = {"member": 5, "expire_at": int(time.time()) + 20}
        node = root / "rust-5"
        ns = node / "node_db/catchains/consensus/v2/current"
        ns.mkdir(parents=True)
        session = bytes([4]) * 32
        (ns / "session-runtime.json").write_text(
            json.dumps(
                {"session": session.hex(), "shard_workchain": -1, "role": "validator"}
            )
        )
        from test_custody_expiry_authority import CustodyAuthorityTests

        helper = CustodyAuthorityTests()
        config, prepared = helper.context(node)
        end = args.signer_expiry_plan["expire_at"]
        config["pq_consensus"]["keys"][0]["expire_at"] = end
        prepared["signer_expire_at"] = end
        helper.save(node, config, prepared)
        log = node / "node.log"
        log.write_text(log.read_text().replace("expire_at 200", f"expire_at {end}"))
        item = {
            "directory": node,
            "process": SimpleNamespace(pid=os.getpid(), returncode=None),
            "start_ticks": Path("/proc/self/stat").read_text().split()[21],
        }
        checkpoint = {
            "block": {"seqno": 10},
            "verified_final_certificates": [
                {"session_id": base64.b64encode(session).decode()}
            ],
        }
        return args, item, checkpoint, ns

    async def test_expiry_authority_is_checked_and_extended_schedule_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, cp, _ns = self.context(root)
            config = json.loads((node["directory"] / "config.json").read_text())
            config["pq_consensus"]["keys"][0]["expire_at"] += 600
            (node["directory"] / "config.json").write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, "Custody window"):
                expiry.SignerExpiry(args, root, node, cp)

    async def test_wrong_session_refusal_does_not_qualify_as_current_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, cp, _ns = self.context(root)
            ctx = expiry.SignerExpiry(args, root, node, cp)
            ctx.deadline = time.monotonic() + 0.01
            (node["directory"] / "node.log").write_text(
                "signing generation expired and retired\nSession wrong broadcast_vote: failed to sign vote: signing journal stopped/retired\n"
            )
            with (
                patch.object(
                    expiry.time, "time", return_value=ctx.plan["expire_at"] + 1
                ),
                self.assertRaises(TimeoutError),
            ):
                await ctx.qualify(args, [], [], [], {}, None, cp, str)

    async def test_authority_cannot_change_after_actual_expiry_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, cp, _ns = self.context(root)
            ctx = expiry.SignerExpiry(args, root, node, cp)
            (node["directory"] / "config.json").write_text("{}")
            with self.assertRaisesRegex(RuntimeError, "authority changed"):
                await ctx.complete({"last_checkpoint": {}})

    async def test_unsigned_completion_allows_only_explicit_config_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, cp, _ns = self.context(root)
            ctx = expiry.SignerExpiry(args, root, node, cp)
            args.expired_member_restart = True
            args.unsigned_original_recovery = True
            ctx.pid = os.getpid() + 100000
            ctx.receipt["phase"] = "qualified_before_interruption"
            config_path = node["directory"] / "config.json"
            config = json.loads(config_path.read_text())
            config.pop("pq_consensus")
            config.pop("validator_keys", None)
            config_path.write_text(json.dumps(config))
            recovered = {
                "last_checkpoint": {},
                "expired_full_node": {},
                "original_obligations_authenticated_and_cleaned": True,
                "unsigned_configuration": {
                    "signing_configuration_removed": True,
                    "after_sha256": expiry.digest(config_path),
                    "before_sha256": ctx.bindings[str(config_path)],
                },
            }
            await ctx.complete(recovered)
            self.assertFalse(ctx.receipt["authority_unchanged"])
            self.assertTrue(ctx.receipt["key_files_unchanged"])
            ctx.receipt["phase"] = "qualified_before_interruption"
            recovered["original_obligations_authenticated_and_cleaned"] = False
            with self.assertRaisesRegex(RuntimeError, "original obligations"):
                await ctx.complete(recovered)
            recovered["original_obligations_authenticated_and_cleaned"] = True
            original_hash = recovered["unsigned_configuration"]["before_sha256"]
            recovered["unsigned_configuration"]["before_sha256"] = "wrong"
            with self.assertRaisesRegex(RuntimeError, "original configuration binding"):
                await ctx.complete(recovered)
            recovered["unsigned_configuration"]["before_sha256"] = original_hash
            prepared = node["directory"] / "validator-prepared.json"
            prepared.write_text("{}")
            with self.assertRaisesRegex(RuntimeError, "outside the explicit"):
                await ctx.complete(recovered)

    async def test_expiry_wait_is_charged_to_original_source_ack_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _old, node, _pending = source_tests.SourceAckTests().context(root)
            cp = {
                "gen_catchain_seqno": 1,
                "verified_final_certificates": [
                    {"session_id": base64.b64encode(bytes([4]) * 32).decode()}
                ],
            }
            start = time.monotonic() - 10
            args = SimpleNamespace(
                source_ack_fault="sync-eio",
                recovery_timeout=180,
                original_recovery_budget={"monotonic": start, "unix": 123.0},
            )
            (root / "second").mkdir()
            new = source.SourceAckFailure(
                args, root, node, cp, directory=root / "second"
            )
            self.assertEqual(new.started, start)
            self.assertEqual(new.deadline, start + 180)
            self.assertEqual(new.receipt["budget_started_at_unix"], 123.0)

    async def test_post_expiry_progress_requires_exact_unexpired_quorum(self):
        for expired_signature in [False, True]:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, node, cp, _ns = self.context(root)
                ctx = expiry.SignerExpiry(args, root, node, cp)
                args.snapshot = Path("cpp")
                args.block_checker = Path("checker")
                block = {
                    "workchain": -1,
                    "shard": "-9223372036854775808",
                    "seqno": 11,
                    "root_hash": "root",
                    "file_hash": "file",
                }
                zero = {**block, "seqno": 0}
                info = {"init": zero, "last": block, "state_root_hash": "state"}
                line = f"Session {ctx.session} broadcast_vote: failed to sign vote: Retired recovery has no signing or voting authority"
                with (node["directory"] / "node.log").open("a") as stream:
                    stream.write(line + "\n")
                checked = {
                    "block": block,
                    "gen_utime": ctx.plan["expire_at"] + 5,
                    "configuration": {
                        "current": {
                            "members": [
                                {"validator_id": str(i), "weight": 17}
                                for i in [0, 2, 4, 5]
                            ]
                        }
                    },
                    "verified_governing_key_blocks": [{}],
                    "key_block": False,
                    "verified_final_certificates": [
                        {
                            "validator_ids": [
                                "0",
                                "2",
                                "5" if expired_signature else "4",
                            ],
                            "verified_weight": 51,
                        }
                    ],
                }

                async def checker(command, log, checked=checked):
                    Path(command[2]).write_text(json.dumps(checked))

                with (
                    patch.object(
                        expiry.time, "time", return_value=ctx.plan["expire_at"] + 10
                    ),
                    patch.object(expiry, "rpc", return_value=info),
                    patch.object(expiry, "cpp_certificate", AsyncMock(return_value={})),
                    patch.object(expiry, "cpp_block", AsyncMock(return_value={})),
                    patch.object(expiry, "native_state", AsyncMock(return_value={})),
                    patch.object(expiry, "child_checked", checker),
                ):
                    if expired_signature:
                        with self.assertRaisesRegex(
                            RuntimeError, "three authorized survivors"
                        ):
                            await ctx.qualify(
                                args,
                                [None] * 6,
                                list(range(6)),
                                [None] * 6,
                                zero,
                                {},
                                cp,
                                str,
                            )
                    else:
                        out = await ctx.qualify(
                            args,
                            [None] * 6,
                            list(range(6)),
                            [None] * 6,
                            zero,
                            {},
                            cp,
                            str,
                        )
                        self.assertEqual(out["block"], block)
                        self.assertEqual(
                            ctx.receipt["phase"], "qualified_before_interruption"
                        )

    async def test_recovery_reuses_observer_started_at_first_successor_checkpoint(self):
        import rotation_fixture as rotation
        import source_ack_partition_fixture as combined

        args = self.args()
        observer = SimpleNamespace(
            started=time.monotonic() - 30,
            started_unix=time.time() - 30,
            qualify=AsyncMock(return_value={"qualified": "early-observer"}),
            complete=AsyncMock(),
        )
        args.signer_expiry_observer = observer
        args.source_ack_partition_restart = True
        args.source_ack_fault = "sync-eio"

        class Context:
            async def complete(self, recovered):
                pass

            def close(self):
                pass

        operation = AsyncMock(return_value=({"last_checkpoint": {"seqno": 100}}, None))
        with (
            patch.object(
                expiry,
                "SignerExpiry",
                side_effect=AssertionError("late observer reconstruction"),
            ),
            patch.object(combined, "SourceAckPartitionRestart", return_value=Context()),
            patch.object(rotation, "_recover_rotation_member", operation),
        ):
            await rotation.recover_rotation_member(
                args,
                Path("root"),
                [None] * 6,
                [None] * 6,
                [None] * 6,
                [{"index": 2}, {"index": 5}],
                {},
                {},
                {"original": "checkpoint"},
                {},
            )
        observer.qualify.assert_awaited_once()
        self.assertEqual(operation.call_args.args[8], {"qualified": "early-observer"})
        self.assertEqual(args.original_recovery_budget["monotonic"], observer.started)
        observer.complete.assert_awaited_once()

    def test_partial_runtime_waits_without_resetting_budget(self):
        for partial in ("", '{"session":'):
            with self.subTest(partial=partial), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, node, cp, ns = self.context(root)
                runtime = ns / "session-runtime.json"
                original = runtime.read_bytes()
                runtime.write_text(partial)
                with (
                    patch.object(expiry.time, "monotonic", return_value=100.0),
                    self.assertRaises(expiry.SignerExpiryRuntimePending),
                ):
                    expiry.SignerExpiry(args, root, node, cp)
                self.assertFalse((root / "signer-expiry/receipt.json").exists())
                runtime.write_bytes(original)
                with patch.object(expiry.time, "monotonic", return_value=100.5):
                    ctx = expiry.SignerExpiry(args, root, node, cp)
                self.assertEqual(ctx.started, 100.0)
                self.assertEqual(ctx.deadline, 100.0 + args.recovery_timeout)

    def test_partial_runtime_cannot_wait_past_original_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, cp, ns = self.context(root)
            (ns / "session-runtime.json").write_text("")
            with (
                patch.object(expiry.time, "monotonic", return_value=100.0),
                self.assertRaises(expiry.SignerExpiryRuntimePending),
            ):
                expiry.SignerExpiry(args, root, node, cp)
            with (
                patch.object(expiry.time, "monotonic", return_value=103.0),
                self.assertRaisesRegex(TimeoutError, "original recovery deadline"),
            ):
                expiry.SignerExpiry(args, root, node, cp)
            self.assertFalse((root / "signer-expiry/receipt.json").exists())

    def test_complete_invalid_manifest_does_not_become_pending(self):
        for invalid in ("null", "[]", "{}"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, node, cp, ns = self.context(root)
                (ns / "session-runtime.json").write_text(invalid)
                with self.assertRaises((TypeError, KeyError)):
                    expiry.SignerExpiry(args, root, node, cp)

    def test_runtime_start_retry_preserves_first_observation_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, cp, ns = self.context(root)
            runtime = ns / "session-runtime.json"
            original = runtime.read_bytes()
            runtime.unlink()
            with (
                patch.object(expiry.time, "monotonic", return_value=100.0),
                self.assertRaisesRegex(RuntimeError, "exact current active MC runtime"),
            ):
                expiry.SignerExpiry(args, root, node, cp)
            self.assertFalse((root / "signer-expiry/receipt.json").exists())
            runtime.write_bytes(original)
            with patch.object(expiry.time, "monotonic", return_value=100.5):
                ctx = expiry.SignerExpiry(args, root, node, cp)
            self.assertEqual(ctx.started, 100.0)
            self.assertEqual(ctx.deadline, 102.0)
            self.assertEqual(ctx.receipt["budget_started_at_unix"], ctx.started_unix)

    def test_runtime_start_wait_cannot_extend_expiry_or_observation_deadline(self):
        for overdue in ["budget", "expiry"]:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, node, cp, ns = self.context(root)
                runtime = ns / "session-runtime.json"
                original = runtime.read_bytes()
                runtime.unlink()
                with (
                    patch.object(expiry.time, "monotonic", return_value=100.0),
                    self.assertRaises(expiry.SignerExpiryRuntimePending),
                ):
                    expiry.SignerExpiry(args, root, node, cp)
                runtime.write_bytes(original)
                if overdue == "budget":
                    with (
                        patch.object(expiry.time, "monotonic", return_value=103.0),
                        self.assertRaisesRegex(
                            TimeoutError, "original recovery deadline"
                        ),
                    ):
                        expiry.SignerExpiry(args, root, node, cp)
                else:
                    with (
                        patch.object(expiry.time, "monotonic", return_value=100.5),
                        patch.object(
                            expiry.time,
                            "time",
                            return_value=args.signer_expiry_plan["expire_at"],
                        ),
                        self.assertRaisesRegex(RuntimeError, "live pre-expiry"),
                    ):
                        expiry.SignerExpiry(args, root, node, cp)
                self.assertFalse((root / "signer-expiry").exists())

    def test_ambiguous_current_runtime_is_fatal_not_startup_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, node, cp, ns = self.context(root)
            other = ns.parent / "duplicate"
            other.mkdir()
            (other / "session-runtime.json").write_bytes(
                (ns / "session-runtime.json").read_bytes()
            )
            with self.assertRaisesRegex(
                RuntimeError, "exact current active MC runtime"
            ) as error:
                expiry.SignerExpiry(args, root, node, cp)
            self.assertNotIsInstance(error.exception, expiry.SignerExpiryRuntimePending)
