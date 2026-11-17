"""A checkpoint-only or voting receiver cannot pass the propagation scenario."""

import copy
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import test_receiver_evidence as receiver_tests
from mixed_matrix import digest
from scenario_execution import check_result, make_profile
from scenario_receiver import RECEIVER_PLAN, check_receiver_evidence
from scenarios import CATALOG, validate
from test_scenario_execution import rotation_result


class ScenarioReceiverTests(unittest.TestCase):
    def test_profile_and_catalog(self):
        catalog = validate(json.loads(CATALOG.read_text()), CATALOG.parent)
        self.assertEqual(catalog["propagation-receiver"]["execution"], "rotation_v1")
        profile = make_profile(
            "propagation-receiver",
            {
                "schema": 1,
                "cpp_revision": "pin",
                "global_version": 16,
                "consensus": {},
                "auth_network_tag": "tag",
            },
            1000,
        )
        self.assertEqual(profile["propagation_receiver"], RECEIVER_PLAN)
        self.assertEqual(profile["successor_members"], [0, 2, 4, 5])

    def test_raw_witness_authority_and_teardown(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "propagation-receiver-evidence"
            directory.mkdir()
            node = root / "network/node7"
            node.mkdir(parents=True)
            (node / "config.json").write_text(json.dumps({"validators": []}))
            checked = receiver_tests.ReceiverEvidenceTests().checked()
            (directory / "checked.json").write_text(json.dumps(checked))
            (directory / "sample.json").write_text(
                json.dumps({"block": {"id": checked["block"]}})
            )
            receipt = {
                "role": "cpp_nonvoting_propagation_receiver",
                "committee_member": False,
                "consensus_keys_configured": False,
                "issuer_member": 0,
                "certificate_flags": 0,
                "certificate_slot": 0,
                "certificate_expire_at": 4600,
                "pid": 123,
                "directory": str(node),
                "checkpoint_full_identity_matches": True,
                "checkpoint": checked["block"],
                "latest": checked["block"],
                "body_state_evidence": {
                    "source": "cpp_nonvoting_receiver",
                    "receiver_body_and_full_state_checked": True,
                    "sample_directory": str(directory),
                    "sample_sha256": digest(directory / "sample.json"),
                    "checked_sha256": digest(directory / "checked.json"),
                    "block": checked["block"],
                    "state_root_hash": "state",
                },
            }
            (root / "propagation-receiver.json").write_text(json.dumps(receipt))
            (root / "processes.json").write_text(
                json.dumps({"propagation_receivers": {"cpp-receiver": 123}})
            )
            stop = {
                "requested_signal": "SIGTERM",
                "alive_before_stop": True,
                "matches_pinned_tester_teardown": True,
                "elapsed_seconds": 1,
                "teardown_limit_seconds": 20,
                "returncode": -15,
            }
            (root / "propagation-receiver-shutdown.json").write_text(json.dumps(stop))
            profile = {"genesis_time": 1000, "propagation_receiver": RECEIVER_PLAN}
            result = rotation_result()
            result["propagation_receiver"] = receipt
            check_result("propagation-receiver", result)
            check_receiver_evidence(root, receipt, profile)
            for field, value in (
                ("committee_member", True),
                ("pid", 321),
                ("certificate_expire_at", 4601),
                ("body_state_evidence", None),
            ):
                bad = copy.deepcopy(receipt)
                bad[field] = value
                with self.assertRaises((ValueError, TypeError)):
                    check_receiver_evidence(root, bad, profile)
            with self.assertRaises(ValueError):
                check_result("rotation-mixed", result)
            for path, value in (
                (node / "config.json", {"validators": ["voter"]}),
                (
                    root / "propagation-receiver-shutdown.json",
                    {**stop, "returncode": -9},
                ),
                (directory / "checked.json", {**checked, "state_root_hash": "wrong"}),
            ):
                original = path.read_bytes()
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    check_receiver_evidence(root, receipt, profile)
                path.write_bytes(original)
