"""Regression controls for the native runtime reference's provenance boundary."""

import json
import tempfile
import unittest
from pathlib import Path

from check_rldp2_runtime import read_frozen


class FrozenProvenanceTests(unittest.TestCase):
    def test_native_reference_and_each_provenance_mutation(self):
        for corpus in ("cases", "boundaries"):
            with self.subTest(corpus=corpus):
                self.check_corpus(corpus)

    def check_corpus(self, corpus):
        root = Path(__file__).parent
        cases = root / f"rldp2_runtime_{corpus}.tsv"
        ids = [
            line.split()[0]
            for line in cases.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        reference = root / (
            "rldp2_runtime_expected.json"
            if corpus == "cases"
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
