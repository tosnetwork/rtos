"""First-intent qualification requires physical recovery and successor evidence."""

import copy
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scenario_execution import check_result
from scenario_matrix import member_id
from scenarios import CATALOG, validate
from test_scenario_execution import rotation_result


def fixture(root, point):
    directory = root / "first-intent-cut"
    directory.mkdir()
    namespace = root / "rust-2/node_db/catchains/consensus/v2/session"
    intents = namespace / "finality-intents"
    (intents / "completed-v1").mkdir(parents=True)
    record = {
        "schema": 1,
        "session_id": "session",
        "slot": 1,
        "candidate_hash": "a" * 64,
        "certificate": "certificate",
    }
    intended = json.dumps(record).encode()
    raw = b"" if point == "before-write" else intended[: len(intended) // 2]
    target = intents / ("1-" + "a" * 64 + ".tmp")
    completed = json.dumps({"schema": 1, "record": record}).encode()
    start = json.dumps(
        {
            k: v
            for k, v in record.items()
            if k not in ("slot", "candidate_hash", "certificate")
        }
    ).encode()
    prepared = root / "rust-2/validator-prepared.json"
    prepared.write_bytes(b"original authority")
    (namespace / "finality-session-start.json").write_bytes(start)
    manifest = json.dumps(
        {
            "session": "session",
            "role": "validator",
            "shard_workchain": -1,
            "catchain_seqno": 0,
        }
    ).encode()
    (namespace / "session-runtime.json").write_bytes(manifest)
    (intents / "completed-v1" / target.with_suffix(".complete").name).write_bytes(
        completed
    )
    sha = lambda data: hashlib.sha256(data).hexdigest()
    inventory = json.dumps(
        [{"path": target.name, "bytes": len(raw), "sha256": sha(raw)}]
    ).encode()
    files = {
        "intent-before.json": raw,
        "intended.json": intended,
        "intent-completed.json": completed,
        "session-start.json": start,
        "intent-directory-at-stop.json": inventory,
        "stopped-process.txt": b"State:\tT (stopped)\nPid:\t100\n",
        "native-stop.marker": f"intent {point} pid=100: {target}\n".encode(),
        "disarmed": b"done",
        "session-runtime.json": manifest,
    }
    for name, data in files.items():
        (directory / name).write_bytes(data)
    receipt = {
        "member": 2,
        "point": point,
        "phase": "rotation_and_first_intent_recovery_verified",
        "recovery_limit_seconds": 180,
        "elapsed_seconds": 20,
        "total_acceptance_elapsed_seconds": 150,
        "manual_database_repair": False,
        "prior_complete_intents": 0,
        "normal_replay_completed": True,
        "stopped_state_verified": True,
        "interruption_returncode": -9,
        "pending_preserved_before_restart": True,
        "successor_mc_wc_post_restart_creators": True,
        "verified_post_restart_vote": True,
        "all_six_mc_four_wc_states_match": True,
        "path": str(target),
        "namespace": str(namespace),
        "old_process": {"pid": 100, "start_ticks": "10"},
        "new_process": {"pid": 200, "start_ticks": "20"},
        "bytes": len(raw),
        "sha256": sha(raw),
        "intended_bytes": len(intended),
        "intended_sha256": sha(intended),
        "session_start_sha256": sha(start),
        "completed_sha256": sha(completed),
        "stopped_directory_inventory_sha256": sha(inventory),
        "prepared_sha256": sha(prepared.read_bytes()),
        "session": record["session_id"],
        "slot": 1,
        "candidate_hash": "a" * 64,
    }
    result = rotation_result()
    for kind in ("mc_creators", "wc_creators"):
        result["epochs"]["after"][kind] = {
            member_id(i): {
                "local_collation_log": "node-restart.log" if i == 2 else "node.log",
                "check": {
                    "verified_final_certificates": [{"validator_ids": [member_id(2)]}]
                },
            }
            for i in (0, 2, 4, 5)
        }
    result["first_intent_cut"] = receipt
    return result


class FirstIntentAdapterTests(unittest.TestCase):
    def test_process_starttime_uses_native_decimal_text_and_numeric_order(self):
        from scenario_first_intent import check_first_intent_result

        with TemporaryDirectory() as tmp:
            result = fixture(Path(tmp), "before-write")
            receipt = result["first_intent_cut"]
            receipt["old_process"]["start_ticks"] = "99"
            receipt["new_process"]["start_ticks"] = "100"
            check_first_intent_result("first-intent-before-write", result)
            for bad in [
                100,
                True,
                None,
                "",
                "0",
                "0100",
                "-1",
                "1.0",
                " 100",
                "１００",
                "98",
            ]:
                with self.subTest(start_ticks=bad):
                    receipt["new_process"]["start_ticks"] = bad
                    with self.assertRaisesRegex(ValueError, "process identity"):
                        check_first_intent_result("first-intent-before-write", result)

    def test_both_cuts_are_wired(self):
        catalog = validate(json.loads(CATALOG.read_text()), CATALOG.parent)
        for point in ("before-write", "after-partial-write"):
            self.assertEqual(
                catalog["first-intent-" + point]["execution"], "rotation_v1"
            )

    def test_physical_recovery_and_restarted_consensus(self):
        from scenario_first_intent import check_first_intent_evidence

        for point in ("before-write", "after-partial-write"):
            with self.subTest(point=point), TemporaryDirectory() as tmp:
                root = Path(tmp)
                result = fixture(root, point)
                check_result("first-intent-" + point, result)
                check_first_intent_evidence(root, result["first_intent_cut"], point)
                changes = [
                    lambda r: r["first_intent_cut"].update(prior_complete_intents=1),
                    lambda r: r["first_intent_cut"].update(
                        total_acceptance_elapsed_seconds=181
                    ),
                    lambda r: r["first_intent_cut"].update(
                        new_process=r["first_intent_cut"]["old_process"]
                    ),
                    lambda r: r["epochs"]["after"]["mc_creators"][member_id(2)].update(
                        local_collation_log="node.log"
                    ),
                    lambda r: r["epochs"]["after"]["mc_creators"][member_id(2)][
                        "check"
                    ].update(verified_final_certificates=[]),
                ]
                for change in changes:
                    bad = copy.deepcopy(result)
                    change(bad)
                    with self.assertRaises(ValueError):
                        check_result("first-intent-" + point, bad)
                with self.assertRaises(ValueError):
                    check_result("rotation-mixed", result)
                for filename in (
                    "intent-before.json",
                    "intended.json",
                    "session-start.json",
                    "intent-completed.json",
                    "intent-directory-at-stop.json",
                    "native-stop.marker",
                    "stopped-process.txt",
                    "session-runtime.json",
                ):
                    path = root / "first-intent-cut" / filename
                    original = path.read_bytes()
                    path.write_bytes(b"substituted")
                    with self.assertRaises(ValueError):
                        check_first_intent_evidence(
                            root, result["first_intent_cut"], point
                        )
                    path.write_bytes(original)
                for relative in (
                    "validator-prepared.json",
                    "node_db/catchains/consensus/v2/session/session-runtime.json",
                    "node_db/catchains/consensus/v2/session/finality-session-start.json",
                ):
                    path = root / "rust-2" / relative
                    original = path.read_bytes()
                    path.write_bytes(b"substituted authority/domain")
                    with self.assertRaises(ValueError):
                        check_first_intent_evidence(
                            root, result["first_intent_cut"], point
                        )
                    path.write_bytes(original)
                target = Path(result["first_intent_cut"]["path"])
                target.write_bytes(b"still pending")
                with self.assertRaises(ValueError):
                    check_first_intent_evidence(root, result["first_intent_cut"], point)
