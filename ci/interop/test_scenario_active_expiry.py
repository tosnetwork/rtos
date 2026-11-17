"""The active expiry adapter must retain the declared below-quorum proof."""

import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scenario_execution import check_result, make_profile
from scenarios import CATALOG, validate
from test_scenario_ack_partition import fixture as ack_partition_fixture
from test_scenario_execution import rotation_result
from test_scenario_restart import fixture as restart_fixture


def active_receipts(root):
    combined, source, _, _ = ack_partition_fixture(root, "sync-eio")
    partition, recovery = restart_fixture(below=True)
    partition.update(
        budget_started_at_unix=90.0,
        surviving_weight=34,
        total_weight=68,
        quorum_weight=46,
    )
    partition["below_quorum_observation"]["plan"].update(
        weights={str(i): 17 for i in (0, 2, 4, 5)},
        total_weight=68,
        quorum_weight=46,
        surviving_weight=34,
        survivor_members=[0, 4],
        unavailable_signer_members=[5],
    )
    result = rotation_result()
    result.update(
        source_ack_partition_restart=combined,
        source_ack_fault=source,
        partition_restart=partition,
        recovery=recovery,
        signer_expiry={},
    )
    return result


class ActiveExpiryTests(unittest.TestCase):
    def test_adapter_and_original_committee(self):
        import json

        catalog = validate(json.loads(CATALOG.read_text()), CATALOG.parent)
        self.assertEqual(catalog["signer-expiry"]["execution"], "rotation_v1")
        template = {
            "schema": 1,
            "cpp_revision": "reference",
            "global_version": 16,
            "consensus": {},
            "auth_network_tag": "tag",
        }
        profile = make_profile("signer-expiry", template, 1000)
        self.assertNotIn("successor_weights", profile)
        self.assertEqual(profile["successor_members"], [0, 2, 4, 5])

    def test_active_expiry_rejects_substituted_quorum(self):
        with TemporaryDirectory() as directory:
            original = active_receipts(Path(directory))
            check_result("signer-expiry", original)
            changes = [
                lambda r: r["partition_restart"].update(surviving_weight=51),
                lambda r: r["partition_restart"]["below_quorum_observation"][
                    "plan"
                ].update(unavailable_signer_members=[]),
                lambda r: r["partition_restart"]["below_quorum_observation"][
                    "plan"
                ].update(survivor_members=[0, 4, 5]),
                lambda r: r["partition_restart"]["below_quorum_observation"].update(
                    observation_count=1
                ),
                lambda r: r["source_ack_partition_restart"].update(
                    budget_started_at_unix=91
                ),
                lambda r: r["source_ack_partition_restart"].update(
                    recovery_limit_seconds=181
                ),
                lambda r: r.update(signer_expiry=None),
            ]
            for change in changes:
                bad = copy.deepcopy(original)
                change(bad)
                with self.assertRaises((ValueError, TypeError)):
                    check_result("signer-expiry", bad)
            with self.assertRaises(ValueError):
                check_result("source-ack-partition-sync-eio", original)
