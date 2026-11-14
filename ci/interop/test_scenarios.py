"""Mutation checks for inventory completeness and control dependencies."""

import copy
import json
import unittest

from scenarios import CATALOG, order, validate


class ScenarioCatalogTest(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads(CATALOG.read_text())

    def test_committed_inventory(self):
        validate(self.catalog, CATALOG.parent)

    def test_control_precedes_mixed_and_is_deduplicated(self):
        entries = validate(self.catalog, CATALOG.parent)
        self.assertEqual(
            order(entries, ["necessary-low-weight-mixed"]),
            ["necessary-low-weight-control", "necessary-low-weight-mixed"],
        )
        self.assertEqual(
            order(entries, ["matrix4-cpp1", "matrix4-cpp2"]),
            ["matrix4-cpp4", "matrix4-cpp1", "matrix4-cpp2"],
        )

    def test_unknown_selection_refused(self):
        with self.assertRaisesRegex(ValueError, "Unknown scenario"):
            order(validate(self.catalog, CATALOG.parent), ["typo"])

    def test_mutated_inventory_refused(self):
        mutations = [
            lambda c: c.update(schema=2),
            lambda c: c["fixture_sources"].pop(),
            lambda c: c["fixture_sources"].append("unreviewed_fixture.py"),
            lambda c: c["scenarios"].append(copy.deepcopy(c["scenarios"][0])),
            lambda c: c["scenarios"][0].update(driver="../rotation_fixture.py"),
            lambda c: c["scenarios"][0].update(depends_on=["missing"]),
            lambda c: c["scenarios"][0].update(depends_on=[c["scenarios"][0]["id"]]),
            lambda c: c["scenarios"][0].update(scope=""),
            lambda c: c["scenarios"][0].update(execution="passed"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                catalog = copy.deepcopy(self.catalog)
                mutate(catalog)
                with self.assertRaises(ValueError):
                    validate(catalog, CATALOG.parent)


if __name__ == "__main__":
    unittest.main()
