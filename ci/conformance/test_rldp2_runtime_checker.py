"""Regression controls for the native runtime reference's provenance boundary."""

import json
import tempfile
import unittest
from pathlib import Path

from check_rldp2_runtime import read_frozen


class FrozenProvenanceTests(unittest.TestCase):
    def test_all_rldp_auxiliary_metadata_uses_current_reference(self):
        root = Path(__file__).parent
        reference = (root / "REFERENCE").read_text().strip()
        metadata = sorted(root.glob("rldp*_metadata.json"))
        self.assertTrue(metadata, "RLDP auxiliary reference metadata is missing")
        for path in metadata:
            with self.subTest(metadata=path.name):
                self.assertEqual(
                    json.loads(path.read_text())["reference_commit"], reference
                )

    def test_native_reference_and_each_provenance_mutation(self):
        for corpus in ("cases", "boundaries", "multipart"):
            with self.subTest(corpus=corpus):
                self.check_corpus(corpus)

    def check_corpus(self, corpus):
        root = Path(__file__).parent
        cases = root / (
            "rldp2_multipart_live_context.tsv"
            if corpus == "multipart"
            else f"rldp2_runtime_{corpus}.tsv"
        )
        ids = [
            line.split()[0]
            for line in cases.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        reference = root / (
            "rldp2_runtime_expected.json"
            if corpus == "cases"
            else "rldp2_multipart_live_expected.json"
            if corpus == "multipart"
            else "rldp2_runtime_boundaries_expected.json"
        )
        self.assertEqual(len(read_frozen(reference, cases, ids)), len(ids))
        for field in ("reference_commit", "input_sha256", "probe_source_sha256"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                document = json.loads(reference.read_text())
                document[field] = "0" * len(document[field])
                mutated = Path(directory) / "reference.json"
                mutated.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    read_frozen(mutated, cases, ids)


if __name__ == "__main__":
    unittest.main()
