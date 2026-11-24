"""Do not choose a partial frontier or silently change its process/source set."""

import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_workchain_original_evidence import inputs
from workchain_recovery_inputs import select_workchain_inputs


class WorkchainRecoveryInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        intent, sealed, self.rows, self.checkpoint, _ = inputs()
        self.pending = SimpleNamespace(
            records=[{"record": intent, "sealed_outputs": {"record": sealed}}]
        )
        (self.root / "wc-publication-capture").mkdir()
        (self.root / "wc-publication-capture/arm.json").write_text(
            json.dumps({"pid": 42, "session": intent["session_id"]})
        )
        (self.root / "checks/1").mkdir(parents=True)
        (self.root / "checks/1/sample.json").write_text(
            json.dumps({"block": "MC-only"})
        )
        (self.root / "checks/2").mkdir()
        (self.root / "checks/2/sample.json").write_text(json.dumps(self.checkpoint))
        (self.root / "recovery").mkdir()
        self.configs = {
            x["name"]: "config" for x in self.checkpoint["workchain"]["states"]
        }

    def select(self, **kwargs):
        return select_workchain_inputs(
            self.root,
            self.pending,
            kwargs.pop("configs", self.configs),
            kwargs.pop("pid", 42),
            kwargs.pop("deadline", time.monotonic() + 10),
            **kwargs,
        )

    def test_exact_complete_selection_records_source(self):
        with patch(
            "workchain_recovery_inputs.read_capture", return_value=self.rows
        ) as read:
            result = self.select(require_approval=True)
            self.assertEqual(result["checkpoint"], self.checkpoint)
            read.assert_called_once_with(
                self.root / "wc-publication-capture",
                42,
                self.pending.records[0]["record"]["session_id"],
            )
            receipt = json.loads(
                (self.root / "recovery/wc-input-selection.json").read_text()
            )
            self.assertTrue(receipt["contains_approval"])
            self.assertEqual(
                receipt["checkpoint"], str(self.root / "checks/2/sample.json")
            )
            with self.assertRaises(FileExistsError):
                self.select()

    def test_changed_pid_session_missing_role_and_sources_refused(self):
        with patch("workchain_recovery_inputs.read_capture", return_value=self.rows):
            with self.assertRaisesRegex(ValueError, "process"):
                self.select(pid=43)
            original = copy.deepcopy(self.pending.records)
            self.pending.records[0]["record"]["session_id"] = "bad"
            with self.assertRaisesRegex(ValueError, "session"):
                self.select()
            self.pending.records = original
            with self.assertRaisesRegex(ValueError, "state source"):
                self.select(configs={})
            with self.assertRaises(TimeoutError):
                self.select(deadline=time.monotonic() - 1)
        with (
            patch("workchain_recovery_inputs.read_capture", return_value=self.rows[:1]),
            self.assertRaisesRegex(ValueError, "complete original"),
        ):
            self.select()
        self.assertFalse((self.root / "recovery/wc-input-selection.json").exists())

    def test_required_approval_is_not_satisfied_by_final_only(self):
        self.pending.records[0]["sealed_outputs"]["record"]["outputs"] = (
            self.pending.records[0]["sealed_outputs"]["record"]["outputs"][:1]
        )
        with patch("workchain_recovery_inputs.read_capture") as read:
            with self.assertRaisesRegex(ValueError, "Approval"):
                self.select(require_approval=True)
            read.assert_not_called()

    def test_candidate_bound_precedes_reading(self):
        for n in range(3, 1026):
            folder = self.root / "checks" / str(n)
            folder.mkdir()
            (folder / "sample.json").write_text("not JSON")
        with (
            patch("workchain_recovery_inputs.read_capture", return_value=self.rows),
            self.assertRaisesRegex(ValueError, "Too many"),
        ):
            self.select()
