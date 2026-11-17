"""Keep every original output obligation without treating it as acceptance."""

import copy
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from expired_member_restart_fixture import (
    PendingIntentRecovery,
    snapshot_sealed_outputs,
)


class PendingOutputSnapshotTests(unittest.TestCase):
    def test_all_outputs_and_raw_bytes_retained(self):
        record = {"slot": 7, "candidate_hash": "a" * 64, "certificate": "original"}
        outputs = [
            {"block_id": "wc-final", "is_final": True, "source_validator": "one"},
            {"block_id": "wc-parent", "is_final": False, "source_validator": "two"},
        ]
        value = {
            "schema": 1,
            "digest": hashlib.sha256(
                json.dumps(record, separators=(",", ":")).encode()
            ).hexdigest(),
            "metadata": dict(record, certificate=""),
            "outputs": outputs,
            "released": False,
        }
        for change in [
            None,
            "digest",
            "metadata",
            "duplicate",
            "empty",
            "flag",
            "symlink",
        ]:
            with self.subTest(change=change), TemporaryDirectory() as temp:
                root = Path(temp)
                source = root / "session/finality-intents" / ("7-" + "a" * 64 + ".json")
                path = source.parent / "outputs-v1" / (source.stem + ".outputs")
                path.parent.mkdir(parents=True)
                source.write_text(json.dumps(record, separators=(",", ":")))
                altered = copy.deepcopy(value)
                if change == "digest":
                    altered["digest"] = "0" * 64
                if change == "metadata":
                    altered["metadata"]["slot"] += 1
                if change == "duplicate":
                    altered["outputs"].append(altered["outputs"][0])
                if change == "empty":
                    altered["outputs"] = []
                if change == "flag":
                    altered["outputs"][0]["is_final"] = 1
                raw = json.dumps(altered, indent=2).encode()
                path.write_bytes(raw)
                if change == "symlink":
                    path.rename(root / "elsewhere")
                    path.symlink_to(root / "elsewhere")
                saved = root / "evidence/original.outputs"
                if change is None:
                    result = snapshot_sealed_outputs(source, record, saved)
                    self.assertEqual(saved.read_bytes(), raw)
                    self.assertEqual(result["record"]["outputs"], outputs)
                    self.assertFalse(result["record"]["released"])
                    captured = PendingIntentRecovery(root, root / "captured")
                    self.assertIn("sealed_outputs", captured.records[0])
                    self.assertEqual(captured.records[0]["sealed_outputs"], result)
                else:
                    with self.assertRaises(RuntimeError):
                        snapshot_sealed_outputs(source, record, saved)
                    self.assertFalse(saved.exists())

    def test_absence_is_not_an_empty_accepted_set(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            saved = root / "evidence"
            self.assertIsNone(snapshot_sealed_outputs(root / "pending.json", {}, saved))
            self.assertFalse(saved.exists())
