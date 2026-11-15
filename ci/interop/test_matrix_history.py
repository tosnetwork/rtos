"""Admission controls shared by direct and historical workchain samples."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from mixed_matrix import record_workchain_creator, require_history_scope


class MatrixHistoryTests(unittest.TestCase):
    def test_scope_requires_every_prerequisite(self):
        good = {
            "workchain_creator_history": True,
            "cpp_count": 1,
            "verify_certificates": True,
            "verify_workchain": True,
        }
        require_history_scope(SimpleNamespace(**good), 4)
        for field, value in [
            ("cpp_count", 0),
            ("verify_certificates", False),
            ("verify_workchain", False),
        ]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                require_history_scope(SimpleNamespace(**{**good, field: value}), 4)
        for count in [3, 6]:
            with self.assertRaises(ValueError):
                require_history_scope(SimpleNamespace(**good), count)

    def test_disabled_history_preserves_existing_modes(self):
        require_history_scope(SimpleNamespace(workchain_creator_history=False), 6)

    def test_creator_and_local_collation_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            check = {
                "created_by": "rust-id",
                "block": {
                    "workchain": 0,
                    "shard": str(-(1 << 63)),
                    "seqno": 3,
                    "root_hash": "root",
                    "file_hash": "file",
                },
            }
            expected = {"rust-id": ("rust", 2)}
            nodes = [{"index": 2, "directory": root}]
            keys, creators = set(), {}
            log = root / "node.log"
            log.write_text(
                "(0:8000000000000000, 2): ValidatorGroup::on_generate_slot: Collation successful\n"
            )
            with self.assertRaisesRegex(RuntimeError, "local collation"):
                record_workchain_creator(
                    check, root, {"seqno": 7}, expected, nodes, keys, creators, root
                )
            self.assertFalse(keys)
            self.assertFalse(creators)
            log.write_text(
                "(0:8000000000000000, 3): ValidatorGroup::on_generate_slot: Collation successful\n"
            )
            record_workchain_creator(
                check, root, {"seqno": 7}, expected, nodes, keys, creators, root
            )
            self.assertEqual(creators["rust-id"]["masterchain_anchor"], {"seqno": 7})
            self.assertEqual(creators["rust-id"]["sample_directory"], str(root))
            self.assertEqual(len(keys), 1)
            with self.assertRaisesRegex(RuntimeError, "unexpected creator"):
                record_workchain_creator(
                    {**check, "created_by": "unknown"},
                    root,
                    {"seqno": 7},
                    expected,
                    nodes,
                    keys,
                    creators,
                    root,
                )


if __name__ == "__main__":
    unittest.main()
