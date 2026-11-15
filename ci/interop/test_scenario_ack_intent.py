"""Intent proof rejects substituted bytes, cut points and completion records."""

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scenario_ack_intent import POINTS, check_intent_evidence


def fixture(root, point):
    directory = root / "source-ack-partition"
    directory.mkdir()
    record = {"session_id": "a" * 64, "slot": 12, "candidate_hash": "b" * 64}
    intended = json.dumps(record).encode()
    before = (
        b""
        if point == "before-write"
        else intended[: len(intended) // 2]
        if point == "after-partial-write"
        else intended
    )
    completed = json.dumps({"schema": 1, "record": record}).encode()
    path = root / "node/finality-intents" / ("12-" + "b" * 64 + ".tmp")
    cut = {
        "point": point,
        "pid": 10,
        "stopped_state_verified": True,
        "normal_replay_completed": True,
        "preserved_after_interruption": True,
        "preserved_before_restart": True,
        "bytes": len(before),
        "sha256": hashlib.sha256(before).hexdigest(),
        "intended_bytes": len(intended),
        "intended_sha256": hashlib.sha256(intended).hexdigest(),
        "completed_sha256": hashlib.sha256(completed).hexdigest(),
        "slot": 12,
        "candidate_hash": "b" * 64,
        "path": str(path),
    }
    for name, raw in [
        ("intent-before.json", before),
        ("intent-original-record.json", intended),
        ("intent-completed.json", completed),
    ]:
        (directory / name).write_bytes(raw)
    (directory / "intent-stopped-process.txt").write_text("State:\tT (stopped)\n")
    (directory / "intent-stop.marker").write_text(f"intent {point} pid=10: {path}\n")
    (directory / "intent-disarmed").touch()
    return (
        {"intent_cut": cut},
        {"session": "a" * 64, "pending_directory": str(root / "node/finality-pending")},
        {"old_process": {"pid": 10}},
    )


class IntentTests(unittest.TestCase):
    def test_all_points_and_mutated_evidence(self):
        for point in POINTS:
            with TemporaryDirectory() as directory:
                root = Path(directory)
                receipt, source, recovery = fixture(root, point)
                check_intent_evidence(root, receipt, source, recovery, point)
                for name in [
                    "intent-before.json",
                    "intent-original-record.json",
                    "intent-completed.json",
                    "intent-stop.marker",
                    "intent-stopped-process.txt",
                ]:
                    p = root / "source-ack-partition" / name
                    before = p.read_bytes()
                    p.write_bytes(b"substituted")
                    with self.assertRaises(ValueError, msg=f"{point}: {name}"):
                        check_intent_evidence(root, receipt, source, recovery, point)
                    p.write_bytes(before)
                receipt["intent_cut"]["normal_replay_completed"] = False
                with self.assertRaises(ValueError):
                    check_intent_evidence(root, receipt, source, recovery, point)


class IntentAdapterTests(unittest.TestCase):
    def test_selected_points_and_composed_receipts(self):
        from scenario_ack_intent import INTENTS, intent_arguments
        from scenario_execution import check_result
        from test_scenario_ack_partition import fixture as combined_fixture
        from test_scenario_execution import rotation_result

        for name, point in INTENTS.items():
            with TemporaryDirectory() as directory:
                root = Path(directory)
                combined, source, partition, recovery = combined_fixture(
                    root, "sync-eio"
                )
                cut = {
                    "point": point,
                    "pid": 10,
                    "stopped_state_verified": True,
                    "normal_replay_completed": True,
                    "preserved_after_interruption": True,
                    "preserved_before_restart": True,
                }
                combined["intent_cut"] = cut
                result = rotation_result()
                result.update(
                    source_ack_partition_restart=combined,
                    source_ack_fault=source,
                    partition_restart=partition,
                    recovery=recovery,
                )
                check_result(name, result)
                args = intent_arguments(name, "/ack.so", "/packet.so")
                self.assertEqual(
                    args[args.index("--source-ack-intent-cut-point") + 1], point
                )
                self.assertIn("--source-ack-intent-stop", args)
                self.assertEqual(args.count("--interrupt-rust-member"), 1)
                with self.assertRaises(ValueError):
                    check_result("source-ack-partition-sync-eio", result)
                cut["point"] = "wrong"
                with self.assertRaises(ValueError):
                    check_result(name, result)
