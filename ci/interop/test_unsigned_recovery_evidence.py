"""Original DB/config binding and late cleanup races must fail closed."""

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from unsigned_recovery_evidence import (
    UnsignedConfiguration,
    check_cleanup_capture,
    complete_unsigned_originals,
    original_paths_removed,
    sha,
)


class UnsignedRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.node = self.root / "node"
        self.node.mkdir()
        (self.node / "node_db").mkdir()
        self.before = {
            "pq_consensus": {"key": "isolated-test-key"},
            "validator_keys": ["signer"],
            "validator_key_ring": {"transport": "isolated-transport-key"},
            "transport": "identity",
        }
        self.config = self.node / "config.json"
        self.config.write_text(json.dumps(self.before))
        self.state = UnsignedConfiguration(self.node, self.root / "configuration")
        self.pending = SimpleNamespace(
            namespaces=self.node / "node_db",
            records=[
                {
                    "path": "session/finality-intents/original.json",
                    "record": {"slot": 1},
                    "sealed_outputs": {"record": {"outputs": ["original"]}},
                }
            ],
        )
        self.path = self.pending.namespaces / self.pending.records[0]["path"]
        self.path.parent.mkdir(parents=True)

    def complete(self):
        return asyncio.run(
            complete_unsigned_originals(
                self.pending,
                self.state,
                deadline=time.monotonic() + 10,
                directory=self.root / "proofs",
            )
        )

    def test_capture_binds_original_pid_inode_and_both_files(self):
        self.path.write_text("original intent")
        output = self.path.parent / "outputs-v1/original.outputs"
        output.parent.mkdir()
        output.write_text("original output")
        control = self.root / "capture"
        control.mkdir()
        (control / "original.json").write_bytes(self.path.read_bytes())
        (control / "original.outputs").write_bytes(output.read_bytes())
        stat = output.stat()
        (control / "captured").write_text(
            f"42\n{stat.st_dev}\n{stat.st_ino}\n{output}\n{self.path}\n"
        )
        item = self.pending.records[0]
        item["sha256"] = sha(self.path.read_bytes())
        item["sealed_outputs"]["sha256"] = sha(output.read_bytes())
        expiry = {"cleanup_capture_before_expiry": True}
        check_cleanup_capture(self.pending, control, expiry, 42)
        with self.assertRaises(ValueError):
            check_cleanup_capture(self.pending, control, expiry, 43)
        with self.assertRaises(ValueError):
            check_cleanup_capture(self.pending, control, {}, 42)
        (control / "original.outputs").write_text("changed")
        with self.assertRaises(ValueError):
            check_cleanup_capture(self.pending, control, expiry, 42)

    def test_explicit_driver_mode_does_not_enable_old_fault_paths(self):
        from rotation_fixture import reject_inactive_custody_faults

        library = self.root / "fixture.so"
        library.touch()
        args = SimpleNamespace(
            unsigned_original_recovery=True,
            intent_cleanup_library=library,
            expired_member_restart=True,
            partition_restart=True,
            signer_expiry_member=5,
            interrupt_rust_member=5,
        )
        reject_inactive_custody_faults(args)
        args.source_ack_fault = "sync-eio"
        with self.assertRaises(SystemExit):
            reject_inactive_custody_faults(args)
        args.source_ack_fault = None
        args.unsigned_original_recovery = False
        with self.assertRaises(SystemExit):
            reject_inactive_custody_faults(args)

    def test_conversion_preserves_transport_and_original_bytes(self):
        expected = dict(self.before)
        del expected["pq_consensus"], expected["validator_keys"]
        self.assertEqual(json.loads(self.config.read_text()), expected)
        self.assertEqual(
            (self.root / "configuration/config-before.json").read_text(),
            json.dumps(self.before),
        )
        self.state.check()

    def test_changed_authority_or_replaced_database_is_rejected(self):
        self.config.write_text(json.dumps(self.before))
        with self.assertRaises(ValueError):
            self.state.check()
        self.config.write_bytes(
            (self.root / "configuration/config-after.json").read_bytes()
        )
        db = self.node / "node_db"
        db.rename(self.node / "old-db")
        db.mkdir()
        with self.assertRaises(ValueError):
            self.state.check()

    def test_pending_or_output_map_is_not_completion(self):
        self.path.write_text("still pending")
        self.assertFalse(self.complete())
        self.path.unlink()
        output = self.path.parent / "outputs-v1/original.outputs"
        output.parent.mkdir()
        output.write_text("still pending")
        self.assertFalse(self.complete())

    def test_missing_set_and_path_escape_are_rejected(self):
        self.pending.records[0]["sealed_outputs"] = None
        with self.assertRaises(ValueError):
            self.complete()
        self.pending.records[0]["path"] = "../outside"
        with self.assertRaises(ValueError):
            original_paths_removed(self.pending)

    def test_broken_symlink_is_not_absence(self):
        self.path.symlink_to(self.root / "nonexistent")
        with self.assertRaises(ValueError):
            original_paths_removed(self.pending)

    def test_cleanup_and_configuration_are_rechecked_after_proofs(self):
        async def verify(*args, directory, **kwargs):
            directory.mkdir(parents=True)
            self.path.write_text("reappeared")
            return [{"block": "original"}]

        with (
            patch("unsigned_recovery_evidence.verify_masterchain_intent", verify),
            self.assertRaisesRegex(ValueError, "reappeared"),
        ):
            self.complete()
        self.assertFalse(
            (self.root / "proofs/original-obligations-checked.json").exists()
        )

    def test_all_sets_verified_before_component_receipt(self):
        calls = []

        async def verify(record, sealed, *, directory, deadline):
            calls.append((record, sealed))
            directory.mkdir(parents=True)
            return [{"block": "original"}]

        with patch("unsigned_recovery_evidence.verify_masterchain_intent", verify):
            self.assertTrue(self.complete())
        self.assertEqual(len(calls), 1)
        result = json.loads(
            (self.root / "proofs/original-obligations-checked.json").read_text()
        )
        self.assertEqual(result["original_sets_checked"], 1)
        self.assertTrue(result["original_pending_and_output_paths_absent"])
